using System;

/// <summary>
/// Упрощённая реализация одного раунда шифра ГОСТ 28147-89.
/// </summary>
public static class GostCipher1
{
    /// <summary>
    /// S-блоки замены (таблицы подстановки ГОСТ 28147-89).
    /// </summary>
    private static readonly byte[,] SBox = new byte[8, 16]
    {
        { 4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 },
        { 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 },
        { 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11 },
        { 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3 },
        { 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2 },
        { 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14 },
        { 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12 },
        { 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 }
    };

    /// <summary>
    /// Применяет S-блоки к 32-битному значению.
    /// </summary>
    /// <param name="value">Входное 32-битное значение.</param>
    /// <returns>Преобразованное 32-битное значение.</returns>
    private static uint ApplySBox(uint value)
    {
        uint result = 0;
        for (int i = 0; i < 8; i++)
        {
            byte nibble = (byte)((value >> (i * 4)) & 0xF);
            byte substituted = SBox[i, nibble];
            result |= (uint)(substituted << (i * 4));
        }
        return result;
    }

    /// <summary>
    /// Циклический сдвиг влево на 11 бит.
    /// </summary>
    /// <param name="value">Входное значение.</param>
    /// <returns>Сдвинутое значение.</returns>
    private static uint RotateLeft11(uint value)
    {
        return (value << 11) | (value >> 21);
    }

    /// <summary>
    /// Выполняет один раунд шифрования блока данных.
    /// </summary>
    /// <param name="block">Блок данных (ровно 8 байт).</param>
    /// <param name="key">Ключ шифрования (ровно 32 байта).</param>
    /// <returns>Зашифрованный блок (8 байт).</returns>
    /// <exception cref="ArgumentNullException">Если block или key равен null.</exception>
    /// <exception cref="ArgumentException">Если block != 8 байт или key != 32 байта.</exception>
    public static byte[] Encrypt(byte[] block, byte[] key)
    {
        if (block == null) throw new ArgumentNullException(nameof(block), "Блок не может быть null.");
        if (key == null) throw new ArgumentNullException(nameof(key), "Ключ не может быть null.");
        if (block.Length != 8) throw new ArgumentException("Блок должен быть ровно 8 байт.");
        if (key.Length != 32) throw new ArgumentException("Ключ должен быть ровно 32 байта.");

        uint left = BitConverter.ToUInt32(block, 0);
        uint right = BitConverter.ToUInt32(block, 4);
        uint subKey = BitConverter.ToUInt32(key, 0);

        uint temp = RotateLeft11(ApplySBox(left + subKey));
        temp = temp ^ right;

        byte[] result = new byte[8];
        Buffer.BlockCopy(BitConverter.GetBytes(temp), 0, result, 0, 4);
        Buffer.BlockCopy(BitConverter.GetBytes(left), 0, result, 4, 4);
        return result;
    }

    /// <summary>
    /// Выполняет один раунд дешифрования блока данных.
    /// </summary>
    /// <param name="block">Зашифрованный блок (ровно 8 байт).</param>
    /// <param name="key">Ключ шифрования (ровно 32 байта).</param>
    /// <returns>Расшифрованный блок (8 байт).</returns>
    /// <exception cref="ArgumentNullException">Если block или key равен null.</exception>
    /// <exception cref="ArgumentException">Если block != 8 байт или key != 32 байта.</exception>
    public static byte[] Decrypt(byte[] block, byte[] key)
    {
        if (block == null) throw new ArgumentNullException(nameof(block), "Блок не может быть null.");
        if (key == null) throw new ArgumentNullException(nameof(key), "Ключ не может быть null.");
        if (block.Length != 8) throw new ArgumentException("Блок должен быть ровно 8 байт.");
        if (key.Length != 32) throw new ArgumentException("Ключ должен быть ровно 32 байта.");

        uint left = BitConverter.ToUInt32(block, 0);
        uint right = BitConverter.ToUInt32(block, 4);
        uint subKey = BitConverter.ToUInt32(key, 0);

        uint temp = RotateLeft11(ApplySBox(right + subKey));
        temp = temp ^ left;

        byte[] result = new byte[8];
        Buffer.BlockCopy(BitConverter.GetBytes(right), 0, result, 0, 4);
        Buffer.BlockCopy(BitConverter.GetBytes(temp), 0, result, 4, 4);
        return result;
    }
}