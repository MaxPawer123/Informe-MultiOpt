<?php
require_once __DIR__ . '/multiotp_helper.php';
require_once __DIR__ . '/auditoria.php';

// Proteccion de acceso a los logs.
if (!mfa_require_authenticated($_SESSION)) {
    registrarAuditoria($conn, mfa_current_user($_SESSION), 'ACCESO_NO_AUTORIZADO', 'Intento en logs.php');
    header('Location: login.php');
    exit();
}

$usuario = mfa_current_user($_SESSION);
registrarAuditoria($conn, $usuario, 'ACCESO_LOGS', 'Consulta de auditoria');

// Consulta de auditoria con prepared statement.
$registros = [];
$limit = 500;
$stmt = $conn->prepare('SELECT id, usuario, accion, detalle, ip, fecha FROM auditoria ORDER BY fecha DESC LIMIT ?');
if ($stmt) {
    $stmt->bind_param('i', $limit);
    if ($stmt->execute()) {
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            $registros[] = $row;
        }
    }
    $stmt->close();
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logs de Auditoria</title>
    <style>
        :root {
            --bg: #f3f7fb;
            --card: #ffffff;
            --text: #1b2a41;
            --muted: #5f6c80;
            --accent: #0f766e;
            --border: #d9e2ec;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            color: var(--text);
            background: radial-gradient(circle at top right, #dff3ef 0%, var(--bg) 45%);
            padding: 20px;
        }

        .wrap {
            max-width: 1100px;
            margin: 0 auto;
        }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            box-shadow: 0 12px 30px rgba(27, 42, 65, 0.08);
        }

        h1 { margin: 0 0 12px; }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            font-size: 0.92rem;
            vertical-align: top;
        }

        th {
            background: #eef2f7;
            font-weight: 700;
        }

        .muted {
            color: var(--muted);
            font-size: 0.9rem;
            margin-bottom: 12px;
        }

        .empty {
            padding: 12px;
            border: 1px dashed var(--border);
            border-radius: 10px;
            color: var(--muted);
        }

        .actions {
            margin-top: 12px;
        }

        .btn {
            display: inline-block;
            text-decoration: none;
            background: var(--accent);
            color: #fff;
            padding: 10px 12px;
            border-radius: 10px;
            font-weight: 700;
        }
    </style>
</head>
<body>
<div class="wrap">
    <section class="card">
        <h1>Logs de Auditoria</h1>
        <p class="muted">Se muestran los ultimos <?php echo htmlspecialchars((string) $limit, ENT_QUOTES, 'UTF-8'); ?> registros.</p>

        <?php if (count($registros) === 0): ?>
            <div class="empty">No hay registros de auditoria.</div>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Usuario</th>
                        <th>Accion</th>
                        <th>Detalle</th>
                        <th>IP</th>
                        <th>Fecha</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($registros as $row): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($row['id'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($row['usuario'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($row['accion'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars((string) $row['detalle'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($row['ip'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($row['fecha'], ENT_QUOTES, 'UTF-8'); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <div class="actions">
            <a class="btn" href="dashboard.php">Volver al dashboard</a>
        </div>
    </section>
</div>
</body>
</html>
