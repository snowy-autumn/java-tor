package snowy.autumn.tor.client;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class Logger {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH_mm_ss_N")
            .withZone(ZoneOffset.UTC);

    FileOutputStream fileOutputStream;
    boolean debug;

    public Logger(boolean debug) {
        this.debug = debug;
        if (debug) {
            try {
                File file = new File(formatter.format(Instant.now()));
                if (!file.exists()) {
                    if (!file.createNewFile()) throw new RuntimeException("Unable to create log file " + file.getName() + '.');
                }
                fileOutputStream = new FileOutputStream(file);
                info("Logger initialised.");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public void log(String priority, String message) {
        if (!debug) return;
        try {
            fileOutputStream.write(('[' + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) + "] [" + priority + "] " + message + '\n').getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void info(String message) {
        log("INFO", message);
    }

    public void warning(String message) {
        log("WARNING", message);
    }

    public void error(String message) {
        log("ERROR", message);
    }

    public void close() {
        try {
            fileOutputStream.close();
        } catch (IOException _) {}
    }

}
