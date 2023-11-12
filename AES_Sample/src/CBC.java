import java.util.Arrays;

public class CBC {
    AES aes;
    byte [] iv = new byte[16];

    public CBC(AES aes){
        this.aes = aes;
    }

    void iv(byte[] value){
        iv = Arrays.copyOfRange(value, 0, 16);  // 16byte로 맞춰줌(패딩)
    }

    public byte[] encrypt(byte[] message, int size) {
        int cur = 0;
        byte[] plaintext;
        for (int i = 0; i < 16; i++) {
            message[i] ^= this.iv[i];
        }
        for (int i = 1; i < size/16; i++) {
            plaintext = Arrays.copyOfRange(message, cur, cur + 16);
            aes.encrypt(plaintext);    // 평문 XOR IV을 암호화

            for (int j = 0; j < 16 && i == 1; j++) {
                message[j] = plaintext[j];  // copy
            }

            for (int j = 0; j < 16; j++, cur++) {
                message[cur + 16] ^= plaintext[j];  // 암호문 XOR 평문
            }
        }
        plaintext = Arrays.copyOfRange(message, cur, cur + 16);
        aes.encrypt(plaintext); // 평문 XOR IV을 암호화
        for (int j = 0; j < 16; j++, cur++) {
            message[cur] = plaintext[j];    // 앞선 암호화한 16byte 블록 XOR 평문
        }
        return message;
    }

    public byte[] decrypt(byte[] message, int size) {
        int cur = 0;
        byte[] buffer = Arrays.copyOf(message, message.length);
        byte[] ciphertext;
        for (int i = 0; i < size; i += 16) {
            ciphertext = Arrays.copyOfRange(message, cur, cur + 16);
            aes.decrypt(ciphertext);
            for (int j = 0; j < 16; j++, cur++) {
                message[cur] = ciphertext[j];
            }
        }
        for (int i = 0; i < 16; i++) {
            message[i] ^= this.iv[i];
        }

        for (int i = 0; i < size - 16; i++) {
            message[i + 16] ^= buffer[i];
        }
        return message;
    }
}