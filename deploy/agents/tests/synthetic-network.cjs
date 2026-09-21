// Synthetic documentation-range traffic only. No sockets or capture APIs.
const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u24 = n => Buffer.from([(n >> 16) & 255, (n >> 8) & 255, n & 255]);
const join = (...buffers) => Buffer.concat(buffers);
const client = Buffer.from([192, 0, 2, 10]);
const server = Buffer.from([198, 51, 100, 20]);
const secret = 'CLOUD_SOC_MUST_NOT_BE_EXPORTED';
function checksum(bytes) {
  let sum = 0;
  for (let i = 0; i < bytes.length; i += 2) sum += (bytes[i] << 8) + (bytes[i + 1] || 0);
  while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
  return (~sum) & 65535;
}
function frame(protocol, payload, reverse = false) {
  const src = reverse ? server : client;
  const dst = reverse ? client : server;
  const ip = Buffer.alloc(20);
  ip[0] = 0x45; ip.writeUInt16BE(20 + payload.length, 2); ip[8] = 64; ip[9] = protocol;
  src.copy(ip, 12); dst.copy(ip, 16); ip.writeUInt16BE(checksum(ip), 10);
  if (protocol === 6) {
    const pseudo = join(src, dst, Buffer.from([0, 6]), u16(payload.length), payload);
    payload.writeUInt16BE(checksum(pseudo), 16);
  }
  const ethernet = Buffer.from(reverse ? '0200000000010200000000020800' : '0200000000020200000000010800', 'hex');
  return join(ethernet, ip, payload);
}
function udp(src, dst, payload, reverse = false) {
  return frame(17, join(u16(src), u16(dst), u16(payload.length + 8), u16(0), payload), reverse);
}
function tcp(src, dst, seq, ack, flags, payload = Buffer.alloc(0), reverse = false) {
  const header = Buffer.alloc(20);
  header.writeUInt16BE(src); header.writeUInt16BE(dst, 2); header.writeUInt32BE(seq, 4); header.writeUInt32BE(ack, 8);
  header[12] = 0x50; header[13] = flags; header.writeUInt16BE(32768, 14);
  return frame(6, join(header, payload), reverse);
}
function dnsName(name) { return join(...name.split('.').map(s => join(Buffer.from([s.length]), Buffer.from(s))), Buffer.from([0])); }
function dnsPair(id, type, answer, srcPort) {
  const question = join(dnsName('cloud-soc.example.test'), u16(type), u16(1));
  const query = join(u16(id), u16(0x0100), u16(1), u16(0), u16(0), u16(0), question);
  const response = join(u16(id), u16(0x8180), u16(1), u16(1), u16(0), u16(0), question,
    Buffer.from('c00c', 'hex'), u16(type), u16(1), Buffer.from('0000003c', 'hex'), u16(answer.length), answer);
  return [udp(srcPort, 53, query), udp(53, srcPort, response, true)];
}
function tlsRecord(type, body) {
  const handshake = join(Buffer.from([type]), u24(body.length), body);
  return join(Buffer.from([0x16, 3, 3]), u16(handshake.length), handshake);
}
function tcpConversation(srcPort, dstPort, request, response) {
  const a = 1000, b = 9000;
  return [
    tcp(srcPort, dstPort, a, 0, 2), tcp(dstPort, srcPort, b, a + 1, 0x12, undefined, true),
    tcp(srcPort, dstPort, a + 1, b + 1, 0x10),
    tcp(srcPort, dstPort, a + 1, b + 1, 0x18, request),
    tcp(dstPort, srcPort, b + 1, a + 1 + request.length, 0x18, response, true),
    tcp(srcPort, dstPort, a + 1 + request.length, b + 1 + response.length, 0x11),
    tcp(dstPort, srcPort, b + 1 + response.length, a + 2 + request.length, 0x11, undefined, true),
    tcp(srcPort, dstPort, a + 2 + request.length, b + 2 + response.length, 0x10)
  ];
}
function syntheticPcap() {
  const name = Buffer.from('cloud-soc.example.test');
  const sniEntry = join(Buffer.from([0]), u16(name.length), name);
  const sni = join(u16(sniEntry.length), sniEntry);
  const extensions = join(u16(0), u16(sni.length), sni);
  const hello = tlsRecord(1, join(Buffer.from([3, 3]), Buffer.alloc(32, 1), Buffer.from([0]), u16(2), u16(0xc02f), Buffer.from([1, 0]), u16(extensions.length), extensions));
  const reply = tlsRecord(2, join(Buffer.from([3, 3]), Buffer.alloc(32, 2), Buffer.from([0]), u16(0xc02f), Buffer.from([0]), u16(0)));
  const frames = [
    ...dnsPair(42, 1, Buffer.from([203, 0, 113, 5]), 51000),
    ...dnsPair(43, 16, join(Buffer.from([secret.length]), Buffer.from(secret)), 51001),
    ...tcpConversation(52000, 443, hello, reply),
    ...tcpConversation(53000, 80, Buffer.from(`POST /?token=${secret} HTTP/1.1\r\nHost: example.test\r\nCookie: ${secret}\r\nContent-Length: ${secret.length}\r\n\r\n${secret}`), Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')),
    ...tcpConversation(54000, 22, Buffer.from('SSH-2.0-synthetic_client\r\n'), Buffer.from('SSH-2.0-synthetic_server\r\n'))
  ];
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4); header.writeUInt16LE(2, 4); header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16); header.writeUInt32LE(1, 20);
  return join(header, ...frames.map((bytes, i) => {
    const record = Buffer.alloc(16);
    record.writeUInt32LE(1700000000 + Math.floor(i / 10)); record.writeUInt32LE((i % 10) * 10000, 4);
    record.writeUInt32LE(bytes.length, 8); record.writeUInt32LE(bytes.length, 12);
    return join(record, bytes);
  }));
}
module.exports = { syntheticPcap, secret };
