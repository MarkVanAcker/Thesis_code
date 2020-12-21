use std::net::TcpStream;
use std::io::{Write, Read};
use std::str;
use message_client::{RaMsgTypes, get_ra_msg_type};


pub struct TCPClient {
    tcp_stream: TcpStream
}


impl TCPClient {

    pub fn new(addr: String, port: u32) -> TCPClient {
        //println!("Connecting to server...");
        TCPClient {
            tcp_stream : TcpStream::connect( [addr,":".to_string(),port.to_string()].concat()).unwrap()
        }
    }

    pub fn send(&mut self,msg: &[u8], tipe: u32){
        let mut buffer= ['\0' as u8;20];

        //create header of form "{msglength}@{MessageType}"
        let mut header = bytebuffer::ByteBuffer::new();
        header.write_bytes((msg.len() as u32).to_string().as_bytes());
        header.write_u8('@' as u8);
        header.write_bytes(tipe.to_string().as_bytes());

        //fill buffer
        header.read(&mut buffer);

        //println!("{}", str::from_utf8(&buffer).unwrap());

        //send header
        self.tcp_stream.write(&buffer);
        //send message
        self.tcp_stream.write(&msg);

    }

    pub fn read(&mut self) -> (Vec<u8>,RaMsgTypes){
        let mut buffer= ['\0' as u8;20];

        //read header
        self.tcp_stream.read_exact(&mut buffer);

        //println!("receive header: {}", str::from_utf8(&buffer).unwrap());

        //parse header
        let header : Vec<&str> = str::from_utf8(&buffer).unwrap().split("@").collect();
        //println!("split1: {}", header[0]);
        //println!("split2: {}", header[1]);

        let msg_size = header[0].parse::<usize>().unwrap();
        //remove trailing nullbytes
        let msg_type = header[1].replace('\0',"").parse::<u32>().unwrap();

        let mut msg_buffer = vec!['\0' as u8; msg_size];

        //println!("messagebuffer size: {}", (msg_buffer.len() as u32).to_string());

        self.tcp_stream.read_exact(&mut msg_buffer);

        (msg_buffer,get_ra_msg_type(msg_type))

    }
}