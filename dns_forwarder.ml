open Lwt
open Dns
open Cohttp
open Cohttp_lwt_unix
open Dns.Packet

(*
 Yojson deriving definitions for the google dns response.
*)
type question_response = {
  qr_name: string [@key "name"];
  qr_typ: int [@key "type"]
}  [@@deriving yojson]

type answer_response = {
  ar_name: string [@key "name"];
  ar_typ: int [@key "type"];
  ttl: int32 [@key "TTL"];
  data: string
} [@@deriving yojson ]

type google_dns_response = {
  status: int [@key "Status"];
  tc: bool [@key "TC"];
  rd: bool [@key "RD"];
  ra: bool [@key "RA"];
  ad: bool [@key "AD"];
  cd: bool [@key "CD"];
  questions: (question_response list [@default []]) [@key "Question"];
  answers: (answer_response list [@default []]) [@key "Answer"];
  additional: (answer_response list [@default []]) [@key "Additional"];
  authorities: (answer_response list [@default []]) [@key "Authority"]
  
} [@@deriving yojson]

(*
  The record types that we handle.
  Anyother type will result in a failure.
*)

type record_type = 
  | R_A
  | R_AAAA
  | R_MX
  | R_CNAME
  | R_SOA

let any fn l = not (List.for_all (fun v -> not (fn v)) l)

let can_handle_record_type q =
  let i = q_type_to_int q in
  let ids = [1;5;6;15;28] in
  any (fun id -> id = i) ids

let int_to_qtype = function
  | 1    -> Q_A
  | 5    -> Q_CNAME
  | 6    -> Q_SOA
  | 15   -> Q_MX
  | 28   -> Q_AAAA

let int_to_record_type = function
  | 1    -> Some R_A
  | 5    -> Some R_CNAME
  | 6    -> Some R_SOA
  | 15   -> Some R_MX
  | 28   -> Some R_AAAA
  | _    -> None

let int_to_rcode n = 
  match n with 
  |  0 -> NoError 
  |  1 -> FormErr
  |  2 -> ServFail
  |  3 -> NXDomain
  |  4 -> NotImp
  |  5 -> Refused
  |  6 -> YXDomain
  |  7 -> YXRRSet
  |  8 -> NXRRSet
  |  9 -> NotAuth
  |  10 -> NotZone
  |  16 -> BadVers
  |  17 -> BadKey
  |  18 -> BadTime
  |  19 -> BadMode
  |  20 -> BadName
  |  21 -> BadAlg

exception ForwarderException


let parse_response str =
  let json = Yojson.Safe.from_string str in
  let r = google_dns_response_of_yojson json in
  match r with
    | Result.Ok r -> r
    | Result.Error err -> raise ForwarderException

let read_question question_response = 
  {
    q_name = Name.of_string question_response.qr_name;
    q_type = int_to_qtype question_response.qr_typ;
    q_class = Q_IN;
    q_unicast = Q_Normal
  }

let parse_mx data = 
  let split_point = String.index data ' ' in
  let length = String.length data in
  let c = int_of_string (String.sub data 0 split_point) in
  let i_length = length - split_point - 1  in
  let i = Name.of_string (String.sub data (split_point + 1) i_length) in
  MX (c, i)

let space_re = Str.regexp " "

let parse_soa data =
    let items = Str.split space_re data in
    let [mn_str; rn_str; serial_str; refresh_str; retry_str; expire_str; minimum_str] = items in
    SOA(Name.of_string mn_str, Name.of_string rn_str,
    Int32.of_string serial_str, Int32.of_string refresh_str, Int32.of_string retry_str, Int32.of_string expire_str, Int32.of_string minimum_str)



let read_answer answer_response =
  let record_type = match int_to_record_type answer_response.ar_typ with 
    | Some record_type -> record_type
    | None -> Lwt_io.printf "No record type found of type %d" answer_response.ar_typ; raise ForwarderException in
  let data_str = answer_response.data in
  let rrtype, rdata = match record_type with 
    | R_A -> (RR_A, A (Ipaddr.V4.of_string_exn data_str))
    | R_SOA -> (RR_SOA, parse_soa data_str)
    | R_AAAA -> (RR_AAAA, AAAA (Ipaddr.V6.of_string_exn  data_str))
    | R_MX -> (RR_MX, (parse_mx data_str))
    | R_CNAME -> (RR_CNAME, CNAME (Name.of_string data_str)) in
  {
    name = Name.of_string answer_response.ar_name;
    cls = RR_IN;
    flush = false;  (* mDNS cache flush bit *)
    ttl = answer_response.ttl;
    rdata = rdata;
  }

let create_response id google_response = 
  let tc = google_response.tc in
  let rd = google_response.rd in
  let ra = google_response.ra in
  let rcode = int_to_rcode (google_response.status) in
  let detail = {
    qr=Response; opcode=Standard; aa=false; tc; rd; ra; rcode
  } in
  let questions = List.map read_question google_response.questions in
  let answers = List.map read_answer google_response.answers in
  let authorities = List.map read_answer google_response.authorities in
  {id; detail; questions; answers; authorities=authorities; additionals=[] }


let get_google_dns_record id typ name =
  let url = Printf.sprintf "https://dns.google.com/resolve?name=%s&type=%d" (Name.to_string name) (q_type_to_int typ) in
  Client.get (Uri.of_string url) >>= fun (resp, body) ->
  body |> Cohttp_lwt_body.to_string >>= fun body ->
  let parsed_response = parse_response body in
  return (create_response id parsed_response)

(* check db first, then fall back to resolver on error *)
let process db resolver ~src ~dst packet =
      let open Packet in
      match packet.questions with
      | [] -> return None; (* no questions in packet *)
      | [q] -> begin
          let answer = Query.(answer q.q_name q.q_type db.Loader.trie) in (* query local db *)
          match answer.Query.rcode with
          | Packet.NoError ->  (* local match *)
            Lwt_io.printf "Local match for %s\n" (Name.to_string q.q_name)
            >>= fun() ->
            return (Some answer)
          | _ -> (* no match, forward *)
            Lwt_io.printf "No local match, forwarding...\n" 
            >>= fun() ->
            if(not (can_handle_record_type q.q_type)) then
              (Lwt_io.printf "Could not recognize request type %d for name %s failing quetly\n" 
                (q_type_to_int q.q_type) (Name.to_string q.q_name)
              >>= fun() -> return None)
            else 
              (get_google_dns_record packet.id q.q_type q.q_name)

            >>= fun result ->
             return (Some (Dns.Query.answer_of_response result))
      end
      | _::_::_ -> return None

let () =
    Lwt_main.run (  
        let address = "127.0.0.1" in (* listen on localhost *)
        let port = 53 in
        let db = Loader.new_db() in (* create new empty db *)
        Dns_resolver_unix.create () (* create resolver using /etc/resolv.conf *)
        >>= fun resolver ->
        let processor = ((Dns_server.processor_of_process (process db resolver)) :> (module Dns_server.PROCESSOR)) in 
        Dns_server_unix.serve_with_processor ~address ~port ~processor)