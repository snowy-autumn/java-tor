package snowy.autumn.tor.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.TimeZone;

public class Utils {

    public static ZonedDateTime getCurrentTime() {
        return Instant.now().atZone(ZoneOffset.UTC);
    }

    public static long parseDate(String date) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            return simpleDateFormat.parse(date).toInstant().getEpochSecond();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

}
