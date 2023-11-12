public class AES {

    protected static final int N = 4;
    protected static final int ROUND = 11;
    protected byte[][] schedule = new byte[ROUND][N * 4];

    final byte[][] rcon = new byte[][]{ // 라운드 상수 값
        {0x1, 0, 0, 0}, {0x2, 0, 0, 0}, {0x4, 0, 0, 0}, {0x8, 0, 0, 0},
        {0x10, 0, 0, 0}, {0x20, 0, 0, 0}, {0x40, 0, 0, 0}, {(byte) 0x80, 0, 0, 0},
        {0x1b, 0, 0, 0}, {0x36, 0, 0, 0}
    };

    char[] sbox = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    char[] inverseSbox = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    void shiftRow(byte[] p) {
        // System.out.println("[Rotation 변환 수행]");
        byte temp, temp2;
        temp = p[1];
        p[1] = p[5];
        p[5] = p[9];
        p[9] = p[13];
        p[13] = temp;
        temp = p[2];
        temp2 = p[6];
        p[2] = p[10];
        p[6] = p[14];
        p[10] = temp;
        p[14] = temp2;
        temp = p[3];
        p[3] = p[15];
        p[15] = p[11];
        p[11] = p[7];
        p[7] = temp;
    }

    void inverseShiftRow(byte[] p) {
        // System.out.println("[Rotation 역변환 수행]");
        byte temp, temp2;
        temp = p[13];
        p[13] = p[9];
        p[9] = p[5];
        p[5] = p[1];
        p[1] = temp;

        temp = p[10];
        temp2 = p[14];
        p[14] = p[6];
        p[10] = p[2];
        p[6] = temp2;
        p[2] = temp;

        temp = p[7];
        p[7] = p[11];
        p[11] = p[15];
        p[15] = p[3];
        p[3] = temp;
    }

    void substitute(byte[] p) {
        // System.out.println("[Substitution 변환 수행]");
        for (int i = 0; i < 16; i++) {
            if (p[i] < 0) {
                p[i] = (byte) sbox[p[i] + 256]; // 음수 처리
            } else {
                p[i] = (byte) sbox[p[i]];
            }
        }
    }

    void inverseSubstitute(byte[] p) {
        // System.out.println("[Substitution 역변환 수행]");
        for (int i = 0; i < 16; i++) {
            int index = p[i] < 0 ? p[i] + 256 : p[i];
            p[i] = (byte) inverseSbox[index];
        }
    }

    void mixColumn(byte[] message) {
        // System.out.println("[MixColumn 연산 수행]");
        byte[][] mixTable = { // 곱할 column 2차원 배열
            {2, 3, 1, 1},
            {1, 2, 3, 1},
            {1, 1, 2, 3},
            {3, 1, 1, 2}
        };
        byte[] a = new byte[4]; // result = a를 변조한 값
        byte eachMessage; // =a
        byte[] mixColumnResult = new byte[16];
        for (int x = 0; x < 4; x++) { // index 값에서 value를 꺼낸다 -> 4x4 행렬
            for (int y = 0; y < 4; y++) {
                for (int i = 0; i < 4; i++) {
                    eachMessage = message[4 * y + i];
//                    System.out.printf("0x%02x  - (index: %d) - Case: %d\n", eachMessage, 4 * y +i,  mixTable[x][i]);
                    if (mixTable[x][i] == 1) {
                        // a * 1 = a
                        a[i] = eachMessage;
                    } else if (mixTable[x][i] == 2) {
                        // a * 2 (First Bit Check X) -> 비트 한개 옮겨줌
                        byte result = (byte) (eachMessage << 1);
                        // a[i] = result < 0 ? (byte) (result + 256) : result;
                        a[i] = result;
                    } else if (mixTable[x][i] == 3) {
                        // a * 3 = a*2+1 (First Bit Check X) -> shift + XOR
                        a[i] = (byte) ((byte) (eachMessage << 1) ^ eachMessage);
                    }
                    // First Bit Check! --> 맨 앞비트가 1인지 확인 후 1일 경우에만 계산
                    // if ((eachMessage & (1 << 7)) != 0 && (mixTable[x][i] != 1)) {
                    if ((byte) eachMessage < 0 && (mixTable[x][i] != 1)) {
                        a[i] = (byte) (a[i] ^ 0x1b); // 오버플로우를 막기 위해서
                    }
                }
                mixColumnResult[4 * y + x] = (byte) (a[0] ^ a[1] ^ a[2] ^ a[3]);
            }
//            System.out.println("==============================");
        }
        // [주의] message = mixColumnResult;
        System.arraycopy(mixColumnResult, 0, message, 0, 16);
    }

    void inverseMixColumn(byte[] message) {
        // System.out.println("[MixColumn 역변환 연산 수행]");
        byte[][] mixTable = {   // 곱할 column 2차원 배열
            {14, 11, 13, 9},
            {9, 14, 11, 13},
            {13, 9, 14, 11},
            {11, 13, 9, 14}
        };
        byte[] a = new byte[4]; // result = a 를 변조한 값
        byte eachMessage; // = a
        byte[] mixColumnResult = new byte[16];
        for (int x = 0; x < 4; x++) {
            for (int y = 0; y < 4; y++) {
                for (int i = 0; i < 4; i++) {
                    eachMessage = message[4 * y + i]; // index 값에서 value를 꺼낸다 -> 4x4 행렬
                    if (mixTable[x][i] == 9) {  // 2 * 2 * 2 + a
                        a[i] = (byte) (galiosDouble(galiosDouble(galiosDouble(eachMessage))) ^ eachMessage);
                    } else if (mixTable[x][i] == 11) {  // (2 * ( 2 * 2 + a )) + a
                        a[i] = (byte) (galiosDouble((byte) (galiosDouble(galiosDouble(eachMessage)) ^ eachMessage)) ^ eachMessage);
                    } else if (mixTable[x][i] == 13) {  // (2 * ( 2 * ( 2 + a ))) + a
                        a[i] = (byte) (galiosDouble(galiosDouble((byte) (galiosDouble(eachMessage) ^ eachMessage))) ^ eachMessage);
                    } else if (mixTable[x][i] == 14) {  // 2 * ( 2 * (2 + a) + a)
                        a[i] = galiosDouble((byte) (galiosDouble((byte) (galiosDouble(eachMessage) ^ eachMessage)) ^ eachMessage));
                    }
                }
                mixColumnResult[4 * y + x] = (byte) (a[0] ^ a[1] ^ a[2] ^ a[3]);
            }
        }
        System.arraycopy(mixColumnResult, 0, message, 0, 16);
    }

    // 갈루아 연산 - a * 2
    static int galiosDoubleWrong(int a) {
        int mostLeftBit = a & (1 << 7);
        a <<= 1;
        if (mostLeftBit == 1) { // 맨 앞이 1일 때 핸들링 못하는 문제
            a ^= 0x1b;
        }
        return a;
    }

    static byte galiosDouble(byte a) {
        int mostLeftBit = a & (1 << 7);
        a <<= 1;
        if (mostLeftBit == 128) {
            a ^= 0x1b;
        }
        return a;
    }

    // Key Scheduling 확인
    public void key(byte[] key) {
        schedule[0] = key; //첫번째
        byte[] temp = new byte[16];
        for (int i = 1; i < ROUND; i++) { // 매 라운드마다 만듦
            for (int j = 0; j < 3; j++) { // 앞 라운드의 마지막 4byte 왼쪽으로 1bit shift / Rotate (2 3 4)
                temp[j] = schedule[i - 1][16 + j - 3];  // temp[0] = (0, 13) / temp[1] = (0, 14) / temp[2] = (0, 15)
            }
            temp[3] = schedule[i - 1][12]; // temp[3] = (0, 12)

            for (int j = 0; j < 4; j++) { // sbox를 이용해 4byte(word 단위) 치환
                if (temp[j] < 0) {
                    ;
                    temp[j] = (byte) sbox[temp[j] + 256];
                } else {
                    temp[j] = (byte) sbox[temp[j]];
                }
            }

            for (int j = 0; j < 4; j++) {   // 해당 round의 상수값과 XOR
                temp[j] = (byte) (temp[j] ^ rcon[i - 1][j]);
            }

            for (int j = 0; j < 4; j++) {   // 앞 round의 첫 4byte와 XOR
                temp[j] = (byte) (schedule[i - 1][j] ^ temp[j]);
                schedule[i][j] = temp[j];
            }

            for (int j = 0; j < 3; j++) {  // 나머지 12byte는 앞 Round의 byte와 자신의 4byte 앞의 것을 XOR해 생성
                for (int k = 0; k < 4; k++) {
                    schedule[i][4 * (j + 1) + k] = (byte) (schedule[i][4 * j + k] ^ schedule[i - 1][
                        4 * (j + 1) + k]);
                }
            }
        }
    }

    public void addRoundKey(byte[] message, int round) {
        for (int i = 0; i < 16; i++) {  // 암호화의 각 단계에서 XOR 연산을 하는데 사용
            message[i] = (byte) (message[i] ^ schedule[round][i]);
        }
    }

    public void encrypt(byte[] message) {
        System.out.println("Round 0");
        addRoundKey(message, 0);
        showArrayMessage(message);
        System.out.println("===================================================================================");
        for (int round = 1; round < ROUND - 1; round++) {
            System.out.printf("Round %d\n", round);
            substitute(message);
            shiftRow(message);
            mixColumn(message);
            addRoundKey(message, round);
            showArrayMessage(message);
            System.out.println("===================================================================================");
        }
        System.out.println("Round 10");
        substitute(message);
        shiftRow(message);
        addRoundKey(message, ROUND - 1);
        showArrayMessage(message);
        System.out.println("===================================================================================");
    }

    public void decrypt(byte[] message) {
        System.out.println("Round 10");
        addRoundKey(message, ROUND - 1);
        showArrayMessage(message);
        System.out.println("===================================================================================");
        for (int round = ROUND - 2; round > 0; round--) {
            System.out.printf("[Decryption] Round %d\n", round);

            System.out.println("inverseShiftRow");  // = Rotation Inverse
            inverseShiftRow(message);
            showArrayMessage(message);

            System.out.println("inverseSubstitute");
            inverseSubstitute(message);
            showArrayMessage(message);

            System.out.println("addRoundKey");
            addRoundKey(message, round);
            showArrayMessage(message);

            System.out.println("inverseMixColumn");
            inverseMixColumn(message);
            showArrayMessage(message);

            System.out.println("===================================================================================");
        }
        System.out.println("Round 0");
        inverseShiftRow(message);
        inverseSubstitute(message);
        addRoundKey(message, 0);
        showArrayMessage(message);
        System.out.println("===================================================================================");
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
