using System;
using System.Text;
using System.Windows.Forms;
using System.Drawing;

namespace GostCipher
{
    /// <summary>
    /// Главная форма приложения шифрования ГОСТ 28147-89.
    /// </summary>
    public partial class Form1 : Form
    {
        /// <summary>
        /// Инициализация компонентов формы.
        /// </summary>
        public Form1()
        {
            InitializeComponent();
            SetupForm();
        }

        /// <summary>
        /// Настройка элементов формы и подсказок.
        /// </summary>
        private void SetupForm()
        {
            this.Text = "Шифр ГОСТ 28147-89";
            this.Size = new Size(520, 480);
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;

            ToolTip toolTip = new ToolTip();

            var lblInput = new Label();
            lblInput.Text = "Исходный текст:";
            lblInput.Location = new Point(20, 20);
            lblInput.Size = new Size(150, 20);

            var txtInput = new TextBox();
            txtInput.Name = "txtInput";
            txtInput.Location = new Point(20, 45);
            txtInput.Size = new Size(460, 60);
            txtInput.Multiline = true;
            toolTip.SetToolTip(txtInput, "Введите текст для шифрования или дешифрования");

            var lblKey = new Label();
            lblKey.Text = "Ключ (32 символа):";
            lblKey.Location = new Point(20, 120);
            lblKey.Size = new Size(220, 20);

            var txtKey = new TextBox();
            txtKey.Name = "txtKey";
            txtKey.Location = new Point(20, 145);
            txtKey.Size = new Size(460, 25);
            toolTip.SetToolTip(txtKey, "Введите ключ — ровно 32 символа (256 бит)");

            var txtOutput = new TextBox();
            txtOutput.Name = "txtOutput";
            txtOutput.Location = new Point(20, 270);
            txtOutput.Size = new Size(460, 120);
            txtOutput.Multiline = true;
            txtOutput.ReadOnly = true;
            txtOutput.BackColor = Color.WhiteSmoke;
            toolTip.SetToolTip(txtOutput, "Здесь отображается результат операции");

            var btnEncrypt = new Button();
            btnEncrypt.Text = "Зашифровать";
            btnEncrypt.Location = new Point(20, 190);
            btnEncrypt.Size = new Size(140, 35);
            toolTip.SetToolTip(btnEncrypt, "Зашифровать введённый текст");
            btnEncrypt.Click += (s, e) => ProcessText(txtInput, txtKey, txtOutput, true);

            var btnDecrypt = new Button();
            btnDecrypt.Text = "Расшифровать";
            btnDecrypt.Location = new Point(175, 190);
            btnDecrypt.Size = new Size(140, 35);
            toolTip.SetToolTip(btnDecrypt, "Расшифровать введённый текст");
            btnDecrypt.Click += (s, e) => ProcessText(txtInput, txtKey, txtOutput, false);

            var btnClear = new Button();
            btnClear.Text = "Очистить";
            btnClear.Location = new Point(330, 190);
            btnClear.Size = new Size(140, 35);
            toolTip.SetToolTip(btnClear, "Очистить все поля");
            btnClear.Click += (s, e) => {
                txtInput.Clear();
                txtKey.Clear();
                txtOutput.Clear();
            };

            var lblOutput = new Label();
            lblOutput.Text = "Результат (hex):";
            lblOutput.Location = new Point(20, 245);
            lblOutput.Size = new Size(150, 20);

            this.Controls.AddRange(new Control[]
            {
                lblInput, txtInput,
                lblKey, txtKey,
                btnEncrypt, btnDecrypt, btnClear,
                lblOutput, txtOutput
            });
        }

        /// <summary>
        /// Обрабатывает шифрование или дешифрование текста.
        /// </summary>
        /// <param name="txtInput">Поле ввода текста.</param>
        /// <param name="txtKey">Поле ввода ключа.</param>
        /// <param name="txtOutput">Поле вывода результата.</param>
        /// <param name="encrypt">True — шифровать, False — дешифровать.</param>
        private void ProcessText(TextBox txtInput, TextBox txtKey,
                                  TextBox txtOutput, bool encrypt)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(txtInput.Text))
                {
                    MessageBox.Show("Введите текст!", "Ошибка",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (string.IsNullOrWhiteSpace(txtKey.Text))
                {
                    MessageBox.Show("Введите ключ!", "Ошибка",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (txtKey.Text.Length != 32)
                {
                    MessageBox.Show("Ключ должен быть ровно 32 символа!", "Ошибка",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                byte[] key = Encoding.UTF8.GetBytes(txtKey.Text);
                byte[] inputBytes = Encoding.UTF8.GetBytes(txtInput.Text);

                int paddedLen = ((inputBytes.Length + 7) / 8) * 8;
                byte[] padded = new byte[paddedLen];
                Buffer.BlockCopy(inputBytes, 0, padded, 0, inputBytes.Length);

                StringBuilder sb = new StringBuilder();

                for (int i = 0; i < paddedLen; i += 8)
                {
                    byte[] block = new byte[8];
                    Buffer.BlockCopy(padded, i, block, 0, 8);

                    byte[] result = encrypt
                        ? GostCipherEngine.Encrypt(block, key)
                        : GostCipherEngine.Decrypt(block, key);

                    foreach (byte b in result)
                        sb.Append(b.ToString("X2") + " ");
                }

                txtOutput.Text = sb.ToString().Trim();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Ошибка: " + ex.Message, "Ошибка",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}