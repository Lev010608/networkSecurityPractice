import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class DiffieHellmanSimulation {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // 1. 用户输入位数
        System.out.print("请输入大素数p位数: ");
        int bitLength = scanner.nextInt();

        // 2. 生成大素数 p 和其元根 a
        BigInteger p = generateLargePrime(bitLength);
        BigInteger a = findPrimitiveRoot(bitLength,p);

        System.out.println("生成的大素数 p: " + p);
        System.out.println("生成的元根 a: " + a);

        // 3. 模拟 Diffie-Hellman 密钥交换
        // 2. 通信双方生成私钥 X_A 和 X_B
        BigInteger xA = generatePrivateKey(p);
        BigInteger xB = generatePrivateKey(p);

        // 3. 计算公开密钥 Y_A 和 Y_B,其中 Y = a^X mod p
        BigInteger yA = a.modPow(xA, p);
        BigInteger yB = a.modPow(xB, p);

        // 4. 传递公开密钥并计算共享密钥 K,K = Y^X mod p
        BigInteger kA = yB.modPow(xA, p);
        BigInteger kB = yA.modPow(xB, p);

        // 5. 输出结果
        System.out.println("Alice 的私钥 X_A: " + xA);
        System.out.println("Bob 的私钥 X_B: " + xB);
        System.out.println("Alice 的公开密钥 Y_A: " + yA);
        System.out.println("Bob 的公开密钥 Y_B: " + yB);
        System.out.println("Alice 计算的共享密钥 K_A: " + kA);
        System.out.println("Bob 计算的共享密钥 K_B: " + kB);

        // 6. 检查共享密钥是否一致
        if (kA.equals(kB)) {
            System.out.println("共享密钥一致，密钥交换成功！");
        } else {
            System.out.println("共享密钥不一致，密钥交换失败！");
        }

        // 4. 模拟攻击者尝试破解
        simulateAttacker(p, a,yA,yB);

        scanner.close();

    }

    // 生成指定位数的大素数1
//    private static BigInteger generateLargePrime(int bitLength) {
//        SecureRandom random = new SecureRandom();
//        return BigInteger.probablePrime(bitLength, random);
//
//    }

    // 生成指定位数的大素数2
    private static BigInteger generateLargePrime(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger probablePrime = BigInteger.probablePrime(bitLength, random);

        // 使用isProbablePrime方法检查生成的数是否可能是素数
        while (!probablePrime.isProbablePrime(80)) {
            probablePrime = BigInteger.probablePrime(bitLength, random);
        }

        return probablePrime;
    }

    // 寻找大素数的元根1
//    private static BigInteger findPrimitiveRoot(BigInteger p) {
//        for (BigInteger a = BigInteger.valueOf(2); a.compareTo(p) < 0; a = a.add(BigInteger.ONE)) {
//            if (a.modPow(p.subtract(BigInteger.ONE), p).equals(BigInteger.ONE)) {
//                return a;
//            }
//        }
//        return null; // 没找到元根，这里可以添加错误处理逻辑
//    }

    // 寻找大素数的元根2
    private static BigInteger findPrimitiveRoot(int bitLength,BigInteger p) {
        BigInteger phi = p.subtract(BigInteger.ONE); // Euler's totient function
        SecureRandom random = new SecureRandom();
        BigInteger a;

        while (true) {
            a = new BigInteger(bitLength, random);
            if (a.compareTo(BigInteger.ONE) > 0 && a.compareTo(p.subtract(BigInteger.ONE)) < 0
                    && a.modPow(phi.divide(BigInteger.TWO), p).compareTo(BigInteger.ONE) != 0) {
                break;
            }
        }

        return a;
    }

    // 计算共享密钥 K，其中 K = Y^X mod p
    private static BigInteger calculateSharedKey(BigInteger publicKey, BigInteger privateKey, BigInteger p) {
        return publicKey.modPow(privateKey, p);
    }

    // 生成私钥 X，要求 1 < X < p-1
    private static BigInteger generatePrivateKey(BigInteger p) {
        SecureRandom random = new SecureRandom();
        BigInteger x;
        do {
            x = new BigInteger(p.bitLength() - 1, random);
        } while (x.compareTo(BigInteger.ONE) <= 0 || x.compareTo(p.subtract(BigInteger.ONE)) >= 0);
        return x;
    }


    //攻击者穷举法破解

    // 模拟攻击者尝试破解
    private static void simulateAttacker(BigInteger p, BigInteger a,BigInteger yA,BigInteger yB) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("模拟攻击者开始尝试破解 Alice 的私钥 X_A,输入回车开始破解：");
        // 模拟攻击者尝试破解 Alice 的私钥 X_A
        scanner.nextLine();
        attack(p, a, yA);

        System.out.println("模拟攻击者开始尝试破解 Bob 的私钥 X_B，,输入回车开始破解：");
        scanner.nextLine();
        // 模拟攻击者尝试破解 Bob 的私钥 X_B
        attack(p, a, yB);
    }

    // 模拟攻击者尝试破解
    private static void attack(BigInteger p, BigInteger a, BigInteger targetPublicKey) {
        BigInteger x = BigInteger.ONE; // 从小到大尝试私钥值
        int attempts = 0;

        long startTime = System.currentTimeMillis();

        while (true) {
            attempts++;

            // 计算对应的公开密钥
            BigInteger computedPublicKey = a.modPow(x, p);

            // 输出每次尝试的私钥值和对应的公开密钥
            System.out.println("尝试次数: " + attempts + ", 私钥值: " + x + ", 计算得到的公开密钥: " + computedPublicKey+", 正确的公开密钥: "+targetPublicKey);

            // 检查是否匹配
            if (computedPublicKey.equals(targetPublicKey)) {
                long endTime = System.currentTimeMillis();
                long elapsedTime = endTime - startTime;

                System.out.println("成功！尝试次数: " + attempts + ", 破译所花时间: " + elapsedTime + " 毫秒, 计算得到的公开密钥: "+ computedPublicKey+", 正确的公开密钥: "+targetPublicKey);
                break;
            }

            x = x.add(BigInteger.ONE); // 尝试下一个私钥值
        }
    }
}
