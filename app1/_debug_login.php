<?php
$conn = new mysqli('localhost', 'root', '', 'login_db');
if ($conn->connect_error) {
    echo 'ERR: ' . $conn->connect_error;
    exit(1);
}
$u = 'admin';
$p = sha1('admin');
$stmt = $conn->prepare('SELECT id, usuario FROM usuarios WHERE usuario=? AND password=?');
$stmt->bind_param('ss', $u, $p);
$stmt->execute();
$res = $stmt->get_result();
echo 'rows=' . $res->num_rows;
