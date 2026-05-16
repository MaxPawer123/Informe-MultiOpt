<?php
require_once __DIR__ . '/conexion.php';

$dbName = '';
$dbResult = $conn->query('SELECT DATABASE() AS db');
if ($dbResult) {
    $row = $dbResult->fetch_assoc();
    $dbName = $row ? $row['db'] : '';
}

$count = 0;
$users = [];
$result = $conn->query('SELECT usuario FROM usuarios');
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $users[] = $row['usuario'];
        $count++;
    }
}

?><!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Debug DB</title>
</head>
<body>
    <h1>Debug DB</h1>
    <p>Base de datos actual: <strong><?php echo htmlspecialchars($dbName, ENT_QUOTES, 'UTF-8'); ?></strong></p>
    <p>Total usuarios: <strong><?php echo $count; ?></strong></p>
    <p>Usuarios: <?php echo htmlspecialchars(implode(', ', $users), ENT_QUOTES, 'UTF-8'); ?></p>
</body>
</html>
