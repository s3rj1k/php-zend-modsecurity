<?php
// Information leak responses for response body inspection tests.
//   leak.php?type=trace   Python style stack trace
//   leak.php?type=sql     SQL error message
//   leak.php?type=clean   normal response

header('Content-Type: text/plain');

$type = $_GET['type'] ?? 'clean';

switch ($type) {
    case 'trace':
        echo "Traceback (most recent call last):\n";
        echo "  File \"/app/handler.py\", line 42, in process\n";
        echo "    return do_work(data)\n";
        echo "  File \"/app/worker.py\", line 13, in do_work\n";
        echo "    raise ValueError('bad input')\n";
        echo "ValueError: bad input\n";
        break;
    case 'sql':
        echo "You have an error in your SQL syntax; check the manual that\n";
        echo "corresponds to your MySQL server version for the right syntax\n";
        echo "to use near 'SELECT * FROM' at line 1\n";
        break;
    case 'webshell':
        // Web shell banner (rule 1110)
        echo "<html><head><title>r57 shell</title></head><body>cmd</body></html>\n";
        break;
    case 'webshell_cmd':
        // Web shell command UI marker (rule 1111)
        echo "<html><body>Ajax/PHP Command Shell v1.0</body></html>\n";
        break;
    case 'dirlist':
        // Directory listing (rule 1112)
        echo "<html><head><title>Index of /var/www/uploads</title></head><body>\n";
        echo "<h1>Index of /var/www/uploads</h1><table><tr><td>file.txt</td></tr></table>\n";
        break;
    case 'srcleak':
        // Raw PHP source as text (rule 1113)
        echo "<?php echo 'leaked source'; ?>\n";
        break;
    case 'clean':
    default:
        echo "OK\n";
        break;
}
