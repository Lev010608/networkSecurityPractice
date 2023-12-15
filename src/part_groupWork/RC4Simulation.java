package part_groupWork;

import java.util.Arrays;
import java.util.Scanner;

public class RC4Simulation {

    public static void main(String[] args) {
        // 创建一个 Scanner 对象来接收用户输入
        Scanner scanner = new Scanner(System.in);

        // 输入明文
        System.out.print("请输入要加密的字符串（仅限字母、中文、数字和标点符号,不能有空格）: ");
        String plaintext = scanner.nextLine();

        // 输入密钥
        System.out.print("请输入密钥（建议密钥的长度应该在 40 到 256 位之间）: ");
        String key = scanner.nextLine();

        // 检查输入是否合法
        if (!isValidInput(plaintext, key)) {
            System.out.println("输入不合法，请重新运行程序并输入有效的字符串和密钥。");
            return;
        }

        // 将明文和密钥转换为字节数组
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] keyBytes = key.getBytes();

        // 加密
        byte[] ciphertext = encryptRC4(plaintextBytes, keyBytes);
        System.out.println("加密后的数据: " + Arrays.toString(ciphertext));

        // 解密（在RC4中，加密和解密使用相同的操作）
        byte[] decryptedText = encryptRC4(ciphertext, keyBytes);
        System.out.println("解密后的数据: " + new String(decryptedText));
    }

    /**
     * RC4加密算法实现
     *
     * @param data 要加密的数据
     * @param key  加密密钥
     * @return 加密后的数据
     */
    public static byte[] encryptRC4(byte[] data, byte[] key) {
        // 初始化S盒和T盒
        int[] S = new int[256];
        int[] T = new int[256];

        // 初始化S盒和T盒的值
        for (int i = 0; i < 256; i++) {
            S[i] = i;
            T[i] = key[i % key.length];
        }

        // 初始置换
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + T[i]) % 256;
            // 交换S[i]和S[j]
            int temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }

        // 生成密文
        int i = 0, k = 0;
        byte[] result = new byte[data.length];
        for (int counter = 0; counter < data.length; counter++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            // 交换S[i]和S[j]
            int temp = S[i];
            S[i] = S[j];
            S[j] = temp;

            // 生成密文字节
            int t = (S[i] + S[j]) % 256;
            int keystream = S[t];
            result[k++] = (byte) (data[counter] ^ keystream);
        }

        return result;
    }

    /**
     * 输入验证方法
     *
     * @param plaintext 明文
     * @param key       密钥
     * @return 是否合法
     */
    private static boolean isValidInput(String plaintext, String key) {
        // 限制字符串只包含字母、数字和标点符号
        return plaintext != null && !plaintext.isEmpty() && plaintext.matches("[\\p{L}0-9\\p{P}]+") &&
                key != null && !key.isEmpty();
    }
}
