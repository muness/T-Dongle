// Same contract check as tools/check-android-status.py of the C tree: Android's production parser must accept all 16 mode/Wi-Fi/USB combinations.
import java.nio.file.*;
import com.muness.tdongle.core.DongleStatus;
public class StatusContract {public static void main(String[] args)throws Exception{
String[] replies=Files.readString(Path.of(args[0])).split("\\f");
if(replies.length!=16)throw new AssertionError("Missing status combinations");
for(int i=0;i<replies.length;i++){DongleStatus s=DongleStatus.parse(replies[i]);
if(!s.mode.equals(i>=8?"tailnet":"adapter") || !s.chipTemperature.contains("55.3") || s.associated()!=((i%8)>=4) || s.usbEnumerated!=((i&2)!=0) || s.usbReady!=((i&1)!=0))throw new AssertionError("Wrong parsed status");}
System.out.println("Rust firmware status: all 16 mode/Wi-Fi/USB combinations accepted by Android's production parser");}}
