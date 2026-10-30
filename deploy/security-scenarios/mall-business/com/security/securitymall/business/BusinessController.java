package com.security.securitymall.business;

import com.security.securitymall.domain.*;
import com.security.securitymall.repository.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

/** Local, authenticated business functions. No seeded records or automatic actions. */
@Controller
@RequestMapping("/soc-business")
public class BusinessController {
    private final UserRepository users;
    private final ItemRepository items;
    private final BusinessAudit audit;
    public BusinessController(UserRepository users, ItemRepository items, BusinessAudit audit) {
        this.users = users; this.items = items; this.audit = audit;
    }
    private User actor(HttpSession session, HttpServletRequest request) {
        String peer = request.getRemoteAddr();
        if (!("127.0.0.1".equals(peer) || "0:0:0:0:0:0:0:1".equals(peer) || "::1".equals(peer)))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Local access required");
        Object login = session.getAttribute("loginUser");
        if (!(login instanceof User)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Login required");
        User current = users.findById(((User)login).getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        if (!"ADMIN".equals(current.getRole())) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Administrator required");
        return current;
    }
    private void csrf(HttpSession session, String token) {
        if (token == null || !token.equals(session.getAttribute("businessCsrf")))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Form expired");
    }
    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
    @GetMapping(produces="text/html;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<String> page(HttpSession session, HttpServletRequest request) {
        actor(session, request);
        String token = (String)session.getAttribute("businessCsrf");
        if (token == null) { token = UUID.randomUUID().toString(); session.setAttribute("businessCsrf", token); }
        String hidden = "<input type='hidden' name='csrf' value='" + token + "'>";
        StringBuilder rows = new StringBuilder();
        for (User u : users.findAll()) rows.append("<option value='").append(u.getId()).append("'>")
            .append(u.getId()).append(" · ").append(escape(String.valueOf(u.getUsername())))
            .append(" · ").append(escape(String.valueOf(u.getRole()))).append("</option>");
        String html = "<!doctype html><html lang='ko'><meta charset='utf-8'><title>쇼핑몰 업무 관리</title>"
            + "<style>body{font:17px sans-serif;max-width:850px;margin:40px auto;line-height:1.7}section{padding:20px;border:1px solid #ddd;margin:20px 0}button{padding:10px}</style>"
            + "<h1>쇼핑몰 업무 관리</h1><a href='/'>쇼핑몰로 돌아가기</a>"
            + "<section><h2>계정 권한 변경</h2><p>선택한 기존 계정의 실제 권한을 변경합니다. 현재 로그인 계정은 변경할 수 없습니다.</p>"
            + "<form method='post' action='/soc-business/role'>" + hidden + "<select name='target'>" + rows + "</select> "
            + "<select name='role'><option>USER</option><option>ADMIN</option></select> <button>권한 저장</button></form></section>"
            + "<section><h2>상품 목록 내보내기</h2><p>현재 DB의 실제 상품을 CSV로 다운로드합니다. 회원 정보는 포함하지 않습니다.</p>"
            + "<form method='post' action='/soc-business/export'>" + hidden + "<button>상품 CSV 다운로드</button></form></section>"
            + "<section><h2>파일 격리 보관</h2><p>최대 5 MiB. 업로드 파일은 공개하거나 실행하지 않고 별도 경로에 격리 보관합니다.</p>"
            + "<form method='post' enctype='multipart/form-data' action='/soc-business/upload'>" + hidden
            + "<input type='file' name='file' required> <button>격리 보관</button></form></section></html>";
        return ResponseEntity.ok().header("Cache-Control", "no-store")
            .header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
            .header("X-Content-Type-Options", "nosniff").body(html);
    }
    @PostMapping("/role")
    public synchronized String role(@RequestParam String csrf, @RequestParam Long target, @RequestParam String role,
                                   HttpSession session, HttpServletRequest request) throws IOException {
        User admin = actor(session, request); csrf(session, csrf);
        if (admin.getId().equals(target) || !("USER".equals(role) || "ADMIN".equals(role)))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid role operation");
        User user = users.findById(target).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        String before = user.getRole() == null ? "none" : user.getRole();
        if (!before.equals(role)) {
            user.setRole(role);
            users.saveAndFlush(user); // repository transaction completes before the success record
            audit.record("app_role", "changed", admin.getId(), Map.of("target_user", audit.account(target),
                "role_before", before, "role_after", role));
        }
        return "redirect:/soc-business";
    }
    private static String csv(String value) {
        String text = value == null ? "" : value;
        if (text.matches("^[=+@\\-\\t\\r].*")) text = "'" + text;
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }
    @PostMapping("/export")
    @ResponseBody
    public ResponseEntity<byte[]> export(@RequestParam String csrf, HttpSession session, HttpServletRequest request) throws IOException {
        User admin = actor(session, request); csrf(session, csrf);
        List<Item> actual = items.findAll();
        StringBuilder csv = new StringBuilder("id,name,category,price,stock\r\n");
        for (Item item : actual) csv.append(item.getId()).append(',').append(csv(item.getName())).append(',')
            .append(csv(item.getCategory())).append(',').append(item.getPrice()).append(',').append(item.getStock()).append("\r\n");
        byte[] content = csv.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        audit.record("app_export", "exported", admin.getId(), Map.of("resource_type", "product_catalog", "record_count", actual.size()));
        return ResponseEntity.ok().header("Content-Disposition", "attachment; filename=products.csv")
            .header("Cache-Control", "no-store").contentType(MediaType.parseMediaType("text/csv;charset=UTF-8")).body(content);
    }
    @PostMapping("/upload")
    @ResponseBody
    public ResponseEntity<String> upload(@RequestParam String csrf, @RequestParam MultipartFile file,
                                        HttpSession session, HttpServletRequest request) throws IOException {
        User admin = actor(session, request); csrf(session, csrf);
        if (file.isEmpty() || file.getSize() > 5L * 1024 * 1024)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File must be between 1 byte and 5 MiB");
        String filename = Optional.ofNullable(file.getOriginalFilename()).orElse("").toLowerCase(Locale.ROOT);
        String risk = null;
        if (filename.matches(".*\\.(exe|dll|com|bat|cmd|ps1|sh|py|jar|jsp|php|html|htm|svg|js)$")) risk = "executable_extension";
        byte[] content = file.getBytes();
        String mime = Optional.ofNullable(file.getContentType()).orElse("");
        boolean png = content.length >= 8 && Arrays.equals(Arrays.copyOf(content, 8), new byte[]{(byte)137,80,78,71,13,10,26,10});
        boolean jpeg = content.length >= 3 && content[0] == (byte)255 && content[1] == (byte)216 && content[2] == (byte)255;
        if (risk == null && (("image/png".equals(mime) && !png) || ("image/jpeg".equals(mime) && !jpeg))) risk = "mime_mismatch";
        Path directory = Path.of(System.getProperty("mall.audit.dir", "audit")).resolve("quarantine").toAbsolutePath();
        if (Files.isSymbolicLink(directory)) throw new IOException("upload_path_invalid");
        Files.createDirectories(directory);
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        String object = UUID.randomUUID() + ".bin";
        Path target = Files.createFile(directory.resolve(object), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.write(target, content, StandardOpenOption.WRITE);
        if (risk != null) audit.record("app_upload", "uploaded", admin.getId(), Map.of("object_name", object, "risk_reason", risk));
        return ResponseEntity.ok().header("Cache-Control", "no-store").contentType(MediaType.TEXT_PLAIN)
            .body("파일 격리 보관 완료. 위험 근거: " + (risk == null ? "확인된 근거 없음" : risk));
    }
}
