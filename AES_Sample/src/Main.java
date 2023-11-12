import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Main {

    // [Ciphertext]
    // [ 0x29 0xc3 0x50 0x5f 0x57 0x14 0x20 0xf6 0x40 0x22 0x99 0xb3 0x1a 0x02 0xd7 0x3a ]

    public static void main(String[] args) {

        // byte[] message = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        byte[] message = "Two One Nine Two".getBytes();
        System.out.println("[Message]");
        showHexMessage(message);
        showArrayMessage(message);
        System.out.println();

        AES aes = new AES();


        // Key Scheduling Test
        System.out.println("[Key] ");
        byte[] key = "Thats my Kung Fu".getBytes();
        showHexMessage(key);
        aes.key(key);
        System.out.println();

        System.out.println("[Key Table]");
        for (int i = 0; i < aes.schedule.length; i++) {
            System.out.printf("[Round %02d] ", i);
            showHexMessage(aes.schedule[i]);
        }
        System.out.println();

        CBC cbc = new CBC(aes);
        cbc.iv("My name is Minsun Han!".getBytes(StandardCharsets.UTF_8));

        message = cbc.encrypt(message, message.length);

        message = cbc.decrypt(message, message.length);
        System.out.println(new String(message));

        // System.out.println("[Encryption Message]");
        // message = aes.encrypt(message);
        // System.out.println();
        //
        // System.out.println("[Ciphertext]");
        // showHexMessage(message);
        // showArrayMessage(message);
        // System.out.println();
        //
        // System.out.println("[Decryption Message]");
        // message = aes.decrypt(message);
        // System.out.println();
        //
        // System.out.println("[Original Message]");
        // System.out.println(new String(message));
        // showHexMessage(message);
        // showArrayMessage(message);
    }

    public static void showHexMessage(byte[] message) {
        System.out.print("[ ");
        for (int i = 0; i < message.length; i++) {
            System.out.printf("0x%02x ", message[i]);
        }
        System.out.println("]");
    }

    public static void showArrayMessage(byte[] message) {
        for (int x = 0; x < 4; x++) {
            for (int y = 0; y < 4; y++) {
                if (message[x + 4 * y] < 0) {
                    System.out.printf("0x%02x ", message[x + 4 * y] + 256);
                } else {
                    System.out.printf("0x%02x ", message[x + 4 * y]);
                }
            }
            System.out.println();
        }
    }
}
