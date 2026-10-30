package com.security.securitymall.business;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/** Real completed operations only; account names/file content are not exported. */
@Component
public class BusinessAudit {
    private final Path directory;
    public BusinessAudit() throws IOException {
        directory = Path.of(System.getProperty("mall.audit.dir", "audit")).toAbsolutePath();
        if (Files.isSymbolicLink(directory)) throw new IOException("audit_path_invalid");
        Files.createDirectories(directory);
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
    }
    public String account(Long id) throws IOException {
        try {
            Path key = directory.resolve("account-hmac.key");
            if (Files.isSymbolicLink(key)) throw new IOException("audit_key_invalid");
            byte[] bytes = Files.readAllBytes(key);
            if (bytes.length != 32) throw new IOException("audit_key_invalid");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(bytes, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(("business-user:" + id).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException error) { throw new IOException("audit_hmac_failed"); }
    }
    private static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 32) out.append(String.format("\\u%04x", (int)c));
            else out.append(c);
        }
        return out.append('"').toString();
    }
    public synchronized void record(String kind, String action, Long actor, Map<String,Object> metadata) throws IOException {
        Map<String,Object> values = new LinkedHashMap<>();
        values.put("schema", "security-scenarios-v1");
        values.put("kind", kind); values.put("action", action); values.put("outcome", "success");
        values.put("actor", account(actor)); values.putAll(metadata);
        StringJoiner json = new StringJoiner(",", "{", "}");
        for (var item : values.entrySet()) {
            Object value = item.getValue();
            json.add(quote(item.getKey()) + ":" + (value instanceof Number || value instanceof Boolean ? value.toString() : quote(value.toString())));
        }
        String line = "{\"timestamp\":" + quote(Instant.now().toString())
            + ",\"operation_id\":" + quote(UUID.randomUUID().toString()) + ",\"security_scenario\":" + json + "}\n";
        Path log = directory.resolve("business-audit.jsonl");
        if (Files.isSymbolicLink(log)) throw new IOException("audit_log_invalid");
        if (!Files.exists(log)) Files.createFile(log, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try (var channel = java.nio.channels.FileChannel.open(log, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            var buffer = StandardCharsets.UTF_8.encode(line);
            while (buffer.hasRemaining()) channel.write(buffer);
            channel.force(true);
        }
    }
}
