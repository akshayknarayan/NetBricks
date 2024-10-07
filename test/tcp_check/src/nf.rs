use e2d2::headers::*;
use e2d2::operators::*;

#[inline]
pub fn tcp_nf<T: 'static + Batch<Header = NullHeader>>(parent: T) -> CompositionBatch {
    parent
        .parse::<MacHeader>()
        .map(Box::new(|pkt| {
            println!("hdr {}", pkt.get_header());
            let payload = pkt.get_payload();
            print!("Payload: ");
            for p in payload {
                print!("{:x} ", p);
            }
            println!("");
        }))
        .parse::<IpHeader>()
        .map(Box::new(|pkt| {
            let hdr = pkt.get_header();
            let flow = hdr.flow().unwrap();
            let payload = pkt.get_payload();
            println!("hdr {} ihl {} offset {}", hdr, hdr.ihl(), hdr.offset());
            println!(
                "payload: {:x} {:x} {:x} {:x}",
                payload[0], payload[1], payload[2], payload[3]
            );
            let (src, dst) = (flow.src_port, flow.dst_port);
            println!("Src {} dst {}", src, dst);
        }))
        .parse::<UdpHeader>()
        .map(Box::new(|pkt| {
            println!("UDP header {}", pkt.get_header());
        }))
        .compose()
}
