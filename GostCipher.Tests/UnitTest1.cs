using NUnit.Framework;
using System;

[TestFixture]
public class GostCipherTests
{
    private byte[] _validBlock;
    private byte[] _validKey;

    [SetUp]
    public void Setup()
    {
        _validBlock = new byte[8] { 1, 2, 3, 4, 5, 6, 7, 8 };
        _validKey = new byte[32];
        for (int i = 0; i < 32; i++) _validKey[i] = (byte)i;
    }

    // ТС-1: шифрование корректного блока даёт результат ≠ исходному
    [Test]
    public void Encrypt_ValidBlock_ReturnsDifferentFromInput()
    {
        byte[] encrypted = GostCipherEngine.Encrypt(_validBlock, _validKey);
        Assert.AreNotEqual(_validBlock, encrypted);
    }

    // ТС-2: обратимость encrypt → decrypt
    [Test]
    public void EncryptDecrypt_ReturnsOriginalBlock()
    {
        byte[] encrypted = GostCipherEngine.Encrypt(_validBlock, _validKey);
        byte[] decrypted = GostCipherEngine.Decrypt(encrypted, _validKey);
        Assert.AreEqual(_validBlock, decrypted);
    }

    // ТС-6: block = null → ArgumentNullException
    [Test]
    public void Encrypt_NullBlock_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            GostCipherEngine.Encrypt(null, _validKey));
    }

    // ТС-7: key = null → ArgumentNullException
    [Test]
    public void Encrypt_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            GostCipherEngine.Encrypt(_validBlock, null));
    }

    // ТС-5: ключ неверной длины → ArgumentException
    [Test]
    public void Encrypt_InvalidKeyLength_ThrowsArgumentException()
    {
        byte[] shortKey = new byte[10];
        Assert.Throws<ArgumentException>(() =>
            GostCipherEngine.Encrypt(_validBlock, shortKey));
    }

    // ТС-4: блок неверной длины → ArgumentException
    [Test]
    public void Encrypt_InvalidBlockLength_ThrowsArgumentException()
    {
        byte[] shortBlock = new byte[4];
        Assert.Throws<ArgumentException>(() =>
            GostCipherEngine.Encrypt(shortBlock, _validKey));
    }

    // ТС-10: два разных ключа дают разный результат
    [Test]
    public void Encrypt_DifferentKeys_ReturnDifferentResults()
    {
        byte[] key2 = new byte[32];
        for (int i = 0; i < 32; i++) key2[i] = (byte)(i + 1);

        byte[] enc1 = GostCipherEngine.Encrypt(_validBlock, _validKey);
        byte[] enc2 = GostCipherEngine.Encrypt(_validBlock, key2);
        Assert.AreNotEqual(enc1, enc2);
    }

    // ТС-11: один ключ всегда даёт одинаковый результат
    [Test]
    public void Encrypt_SameInputTwice_ReturnsSameResult()
    {
        byte[] enc1 = GostCipherEngine.Encrypt(_validBlock, _validKey);
        byte[] enc2 = GostCipherEngine.Encrypt(_validBlock, _validKey);
        Assert.AreEqual(enc1, enc2);
    }
}