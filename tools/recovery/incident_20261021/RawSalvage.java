package org.elasticsearch.index.translog;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Constructor;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.*;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.*;
import org.apache.lucene.store.*;
import org.apache.lucene.util.*;
import org.elasticsearch.common.bytes.*;
import org.elasticsearch.common.compress.CompressorFactory;
import org.elasticsearch.index.mapper.Uid;

/** Export only from an archived shard. Never instantiate an Elasticsearch engine. */
public class RawSalvage {
    static String b64(byte[] data) { return Base64.getEncoder().encodeToString(data); }
    static void row(BufferedWriter out, String id, long sequence, byte[] source, String origin) throws IOException {
        out.write("{\"id_b64\":\"" + b64(id.getBytes(java.nio.charset.StandardCharsets.UTF_8))
            + "\",\"seq_no\":" + sequence + ",\"source_b64\":\"" + b64(source)
            + "\",\"origin\":\"" + origin + "\"}\n");
    }
    public static void main(String[] args) throws Exception {
        org.elasticsearch.logging.internal.spi.LoggerFactory.setInstance(
            new org.elasticsearch.common.logging.internal.LoggerFactoryImpl());
        Path archive = Path.of(args[0]), output = Path.of(args[1]);
        long good = 0, missingFields = 0, translogIndexes = 0, deletes = 0, noops = 0;
        boolean segmentsComplete = false, translogComplete = false;
        String segmentError = "", translogError = "";
        String uuid;
        try (Directory directory = FSDirectory.open(archive.resolve("index"))) {
            SegmentInfos infos = SegmentInfos.readLatestCommit(directory);
            uuid = infos.getUserData().get(Translog.TRANSLOG_UUID_KEY);
            Constructor<SegmentReader> openSegment = SegmentReader.class.getDeclaredConstructor(
                SegmentCommitInfo.class, int.class, IOContext.class);
            openSegment.setAccessible(true);
            try (BufferedWriter out = Files.newBufferedWriter(output.resolve("segments.ndjson"), StandardOpenOption.CREATE_NEW)) {
                for (SegmentCommitInfo info : infos) {
                    if (info.info.name.equals("_768")) continue;
                    try (SegmentReader reader = openSegment.newInstance(info, infos.getIndexCreatedVersionMajor(), IOContext.READONCE)) {
                        reader.checkIntegrity();
                        Bits live = reader.getLiveDocs();
                        StoredFields stored = reader.storedFields();
                        NumericDocValues sequences = reader.getNumericDocValues("_seq_no");
                        for (int doc = 0; doc < reader.maxDoc(); doc++) {
                            if (live != null && !live.get(doc)) continue;
                            Document document = stored.document(doc);
                            BytesRef id = document.getBinaryValue("_id");
                            BytesRef source = document.getBinaryValue("_source");
                            if (id == null || source == null || sequences == null || !sequences.advanceExact(doc)) {
                                missingFields++;
                                continue;
                            }
                            BytesReference bytes = new BytesArray(source.bytes, source.offset, source.length);
                            row(out, Uid.decodeId(id), sequences.longValue(),
                                BytesReference.toBytes(CompressorFactory.uncompressIfNeeded(bytes)), "segments");
                            good++;
                        }
                    }
                }
                segmentsComplete = missingFields == 0 && good == 215564;
            } catch (Exception | LinkageError e) { segmentError = e.getClass().getName(); e.printStackTrace(System.err); }
        }
        Path log = archive.resolve("translog/translog-430.tlog");
        try (BufferedWriter out = Files.newBufferedWriter(output.resolve("translog.ndjson"), StandardOpenOption.CREATE_NEW);
             FileChannel channel = FileChannel.open(log, StandardOpenOption.READ)) {
            // The saved checkpoint belongs to absent generation 424. This scan
            // uses file length only in memory and verifies each record checksum.
            // It does not make the reconstructed boundary an authoritative commit.
            Checkpoint boundary = new Checkpoint(channel.size(), Integer.MAX_VALUE, 430,
                0, Long.MAX_VALUE, -1, 430, -2);
            try (TranslogReader reader = TranslogReader.open(channel, log, boundary, uuid)) {
                TranslogSnapshot snapshot = new TranslogSnapshot(reader, channel.size());
                Field position = TranslogSnapshot.class.getDeclaredField("position");
                position.setAccessible(true);
                Field pending = TranslogSnapshot.class.getDeclaredField("pendingExploded");
                pending.setAccessible(true);
                while (position.getLong(snapshot) < channel.size() || !((Deque<?>) pending.get(snapshot)).isEmpty()) {
                    Translog.Operation operation = snapshot.next();
                    if (operation == null) break;
                    if (operation instanceof Translog.Index index) {
                        row(out, Uid.decodeId(index.uid()), index.seqNo(), BytesReference.toBytes(index.source()), "translog");
                        translogIndexes++;
                    } else if (operation instanceof Translog.Delete delete) {
                        out.write("{\"delete_id_b64\":\"" + b64(Uid.decodeId(delete.uid()).getBytes(java.nio.charset.StandardCharsets.UTF_8))
                            + "\",\"seq_no\":" + delete.seqNo() + "}\n");
                        deletes++;
                    } else { noops++; }
                }
                translogComplete = position.getLong(snapshot) == channel.size() && ((Deque<?>) pending.get(snapshot)).isEmpty();
            }
        } catch (Exception | LinkageError e) { translogError = e.getClass().getName(); e.printStackTrace(System.err); }
        String summary = "{\"segment_export_complete\":" + segmentsComplete + ",\"segment_documents\":" + good
            + ",\"missing_stored_fields\":" + missingFields + ",\"segment_error\":\"" + segmentError
            + "\",\"translog_scan_complete\":" + translogComplete + ",\"translog_index_operations\":" + translogIndexes
            + ",\"translog_delete_operations\":" + deletes + ",\"translog_noops\":" + noops
            + ",\"translog_error\":\"" + translogError + "\"}";
        Files.writeString(output.resolve("java-summary.json"), summary, StandardOpenOption.CREATE_NEW);
        System.out.println(summary);
    }
}
