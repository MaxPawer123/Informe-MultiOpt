<?php
require_once __DIR__ . "/multiotp_helper.php";
require_once __DIR__ . "/auditoria.php";

// Esta pantalla requiere autenticacion completa con OTP.
if (!mfa_require_authenticated($_SESSION)) {
    // Auditoria de intento no autorizado.
    registrarAuditoria($conn, mfa_current_user($_SESSION), 'ACCESO_NO_AUTORIZADO', 'Intento en usuarios.php');
    header('Location: login.php');
    exit();
}
$usuarioSesion = mfa_current_user($_SESSION);

$accion = isset($_GET["accion"]) ? $_GET["accion"] : "";
$mensaje = "";
$error = "";
$qrDataUri = '';
$createResult = null;
$qrResult = null;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $tipo = isset($_POST["tipo"]) ? $_POST["tipo"] : "";

    if ($tipo === "crear") {
        $nuevoUsuario = isset($_POST["usuario"]) ? trim($_POST["usuario"]) : "";
        $nuevaPassword = isset($_POST["password"]) ? $_POST["password"] : "";

        if ($nuevoUsuario === "" || $nuevaPassword === "") {
            $error = "Usuario y contrasena son obligatorios para crear.";
        } else {
            $check = $conn->prepare("SELECT usuario FROM usuarios WHERE usuario = ?");
            $check->bind_param("s", $nuevoUsuario);
            $check->execute();
            $exists = $check->get_result();

            if ($exists->num_rows > 0) {
                $error = "El usuario ya existe.";
            } else {
                $hash = sha1($nuevaPassword);
                $stmt = $conn->prepare("INSERT INTO usuarios (usuario, password) VALUES (?, ?)");
                $stmt->bind_param("ss", $nuevoUsuario, $hash);

                if ($stmt->execute()) {
                    $mensaje = "Usuario creado correctamente.";
                } else {
                    $error = "No se pudo crear el usuario.";
                }
            }
        }
    }

    if ($tipo === "editar") {
        $usuarioOriginal = isset($_POST["usuario_original"]) ? trim($_POST["usuario_original"]) : "";
        $usuarioNuevo = isset($_POST["usuario"]) ? trim($_POST["usuario"]) : "";
        $passwordNueva = isset($_POST["password"]) ? $_POST["password"] : "";

        if ($usuarioOriginal === "" || $usuarioNuevo === "") {
            $error = "Datos incompletos para editar el usuario.";
        } else {
            if ($usuarioOriginal !== $usuarioNuevo) {
                $check = $conn->prepare("SELECT usuario FROM usuarios WHERE usuario = ?");
                $check->bind_param("s", $usuarioNuevo);
                $check->execute();
                $exists = $check->get_result();

                if ($exists->num_rows > 0) {
                    $error = "El nuevo nombre de usuario ya esta en uso.";
                }
            }

            if ($error === "") {
                if ($passwordNueva !== "") {
                    $hash = sha1($passwordNueva);
                    $stmt = $conn->prepare("UPDATE usuarios SET usuario = ?, password = ? WHERE usuario = ?");
                    $stmt->bind_param("sss", $usuarioNuevo, $hash, $usuarioOriginal);
                } else {
                    $stmt = $conn->prepare("UPDATE usuarios SET usuario = ? WHERE usuario = ?");
                    $stmt->bind_param("ss", $usuarioNuevo, $usuarioOriginal);
                }

                if ($stmt->execute()) {
                    $mensaje = "Usuario actualizado correctamente.";
                } else {
                    $error = "No se pudo actualizar el usuario.";
                }
            }
        }
    }

    if ($tipo === "eliminar") {
        $usuarioEliminar = isset($_POST["usuario"]) ? trim($_POST["usuario"]) : "";

        if ($usuarioEliminar === "") {
            $error = "No se indico el usuario a eliminar.";
        } elseif ($usuarioEliminar === $usuarioSesion) {
            $error = "No puedes eliminar el usuario de la sesion actual.";
        } else {
            $stmt = $conn->prepare("DELETE FROM usuarios WHERE usuario = ?");
            $stmt->bind_param("s", $usuarioEliminar);

            if ($stmt->execute()) {
                $mensaje = "Usuario eliminado correctamente.";
            } else {
                $error = "No se pudo eliminar el usuario.";
            }
        }
    }

    if ($tipo === "generar_2fa") {
        $usuarioGenerar = isset($_POST["usuario"]) ? trim($_POST["usuario"]) : "";

        if ($usuarioGenerar === "") {
            $error = "No se indico el usuario para generar 2FA.";
        } else {
            if (!mfa_multiotp_available()) {
                $error = 'multiOTP no esta disponible en el servidor.';
            } else {
                $setup = mfa_create_token_and_qr($usuarioGenerar);
                $createResult = $setup['create_result'];
                $qrResult = $setup['qr_result'];
                $qrDataUri = $setup['qr_data_uri'];

                if ($setup['ok'] && $qrDataUri !== '') {
                    $mensaje = "Token TOTP generado para usuario: " . $usuarioGenerar;
                } elseif ($setup['ok']) {
                    $mensaje = "Token creado, pero no se genero la imagen QR.";
                } else {
                    $error = "No se pudo crear el token OTP para el usuario.";
                }
            }
        }
    }
}

$usuarioEdicion = "";
if ($accion === "editar" && isset($_GET["usuario"])) {
    $usuarioEdicion = trim($_GET["usuario"]);
}

$usuarios = [];
$q = $conn->query("SELECT usuario FROM usuarios ORDER BY usuario ASC");
if ($q) {
    while ($row = $q->fetch_assoc()) {
        $usuarios[] = $row["usuario"];
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ABM de Usuarios</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #f0f4f8;
            --card: #ffffff;
            --text: #1b2a41;
            --muted: #64748b;
            --accent: #0f766e;
            --accent-dark: #115e59;
            --accent-light: #ccfbf1;
            --danger: #b91c1c;
            --danger-dark: #991b1b;
            --danger-light: #fee2e2;
            --border: #e2e8f0;
            --ok-bg: #f0fdf4;
            --ok-text: #166534;
            --err-bg: #fef2f2;
            --err-text: #991b1b;
            --tfa-bg: #0e7490;
            --tfa-dark: #0c6480;
            --shadow: 0 4px 24px rgba(15, 118, 110, 0.08);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            min-height: 100vh;
            font-family: 'Inter', 'Segoe UI', sans-serif;
            color: var(--text);
            background: linear-gradient(135deg, #e0f7f4 0%, #f0f4f8 50%, #eef2f7 100%);
            padding: 24px 16px;
        }

        .wrap {
            max-width: 960px;
            margin: 0 auto;
            display: grid;
            gap: 20px;
        }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 24px;
            box-shadow: var(--shadow);
            transition: box-shadow 0.2s;
        }

        h1 { font-size: 1.6rem; font-weight: 800; color: var(--text); margin-bottom: 6px; }
        h2 { font-size: 1.2rem; font-weight: 700; color: var(--text); margin-bottom: 14px; }

        .msg, .err {
            padding: 12px 16px;
            border-radius: 12px;
            margin-bottom: 14px;
            font-size: 0.92rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .msg { background: var(--ok-bg); color: var(--ok-text); border: 1px solid #bbf7d0; }
        .err { background: var(--err-bg); color: var(--err-text); border: 1px solid #fecaca; }

        .grid {
            display: grid;
            gap: 14px;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        }

        label {
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            font-size: 0.88rem;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        input {
            width: 100%;
            padding: 10px 14px;
            border-radius: 10px;
            border: 1.5px solid var(--border);
            font-size: 0.95rem;
            font-family: inherit;
            color: var(--text);
            background: #f8fafc;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(15,118,110,0.12);
            background: #fff;
        }

        .btn {
            border: none;
            border-radius: 10px;
            padding: 10px 18px;
            color: #fff;
            cursor: pointer;
            font-weight: 700;
            font-size: 0.9rem;
            font-family: inherit;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: transform 0.15s, box-shadow 0.15s, background 0.15s;
        }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 6px 16px rgba(0,0,0,0.15); }
        .btn:active { transform: translateY(0); }

        .btn-main { background: linear-gradient(135deg, var(--accent), var(--accent-dark)); }
        .btn-main:hover { background: linear-gradient(135deg, var(--accent-dark), #0d4d48); }
        .btn-2fa { background: linear-gradient(135deg, #0891b2, #0e7490); }
        .btn-2fa:hover { background: linear-gradient(135deg, #0e7490, #0c5c70); }
        .btn-danger { background: linear-gradient(135deg, #ef4444, var(--danger)); }
        .btn-danger:hover { background: linear-gradient(135deg, var(--danger), var(--danger-dark)); }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
        }
        thead th {
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--muted);
            padding: 10px 12px;
            border-bottom: 2px solid var(--border);
        }
        tbody td {
            padding: 14px 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
            font-size: 0.95rem;
        }
        tbody tr:last-child td { border-bottom: none; }
        tbody tr:hover { background: #f8fafc; }

        .actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .top-links {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 14px;
        }

        form.inline { display: inline; }

        /* ── 2FA Result Card ── */
        .result-2fa-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 18px;
        }
        .result-2fa-header .icon-2fa {
            width: 44px; height: 44px;
            background: linear-gradient(135deg, #0891b2, #0f766e);
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.3rem;
            flex-shrink: 0;
        }
        .result-2fa-grid {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 20px;
            align-items: start;
        }
        .qr-container {
            background: linear-gradient(135deg, #f0fdf9, #e0f2fe);
            border: 2px dashed #a7f3d0;
            border-radius: 16px;
            padding: 20px;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
            min-width: 200px;
        }
        .qr-container img {
            width: 180px; height: 180px;
            border-radius: 12px;
            background: #fff;
            padding: 10px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.12);
        }
        .qr-label {
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .output-label {
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--muted);
            margin-bottom: 6px;
        }
        .code-block {
            background: #0f172a;
            color: #7dd3fc;
            border-radius: 12px;
            padding: 14px 16px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.83rem;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-word;
            border: 1px solid #1e293b;
        }

        /* ── Custom Modal ── */
        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(15, 23, 42, 0.55);
            backdrop-filter: blur(6px);
            -webkit-backdrop-filter: blur(6px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.25s ease;
        }
        .modal-overlay.active {
            opacity: 1;
            pointer-events: all;
        }
        .modal-box {
            background: #fff;
            border-radius: 22px;
            padding: 32px 28px 24px;
            max-width: 400px;
            width: 90%;
            box-shadow: 0 24px 60px rgba(0,0,0,0.2);
            transform: scale(0.88) translateY(20px);
            transition: transform 0.3s cubic-bezier(0.34,1.56,0.64,1), opacity 0.25s ease;
            opacity: 0;
            position: relative;
        }
        .modal-overlay.active .modal-box {
            transform: scale(1) translateY(0);
            opacity: 1;
        }
        .modal-icon {
            width: 56px; height: 56px;
            background: linear-gradient(135deg, #0891b2, #0f766e);
            border-radius: 16px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.6rem;
            margin: 0 auto 16px;
        }
        .modal-title {
            font-size: 1.15rem;
            font-weight: 800;
            color: var(--text);
            text-align: center;
            margin-bottom: 8px;
        }
        .modal-desc {
            font-size: 0.9rem;
            color: var(--muted);
            text-align: center;
            margin-bottom: 24px;
            line-height: 1.5;
        }
        .modal-user-badge {
            display: inline-block;
            background: var(--accent-light);
            color: var(--accent-dark);
            font-weight: 700;
            font-size: 0.88rem;
            padding: 3px 12px;
            border-radius: 20px;
            margin-bottom: 20px;
        }
        .modal-actions {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }
        .modal-cancel {
            background: #f1f5f9;
            color: var(--text);
            border: none;
            border-radius: 10px;
            padding: 10px 20px;
            font-weight: 600;
            font-size: 0.9rem;
            font-family: inherit;
            cursor: pointer;
            transition: background 0.15s;
        }
        .modal-cancel:hover { background: #e2e8f0; }
        .modal-confirm {
            background: linear-gradient(135deg, #0891b2, #0f766e);
            color: #fff;
            border: none;
            border-radius: 10px;
            padding: 10px 22px;
            font-weight: 700;
            font-size: 0.9rem;
            font-family: inherit;
            cursor: pointer;
            transition: opacity 0.15s, transform 0.15s;
        }
        .modal-confirm:hover { opacity: 0.9; transform: translateY(-1px); }

        @media (max-width: 600px) {
            .result-2fa-grid { grid-template-columns: 1fr; }
            .qr-container { min-width: unset; }
        }
    </style>
</head>
<body>
<div class="wrap">
    <section class="card">
        <h1>ABM de usuarios</h1>
        <p>Gestion simple de altas, bajas y modificaciones.</p>
        <p>Usuario actual: <strong><?php echo htmlspecialchars($usuarioSesion, ENT_QUOTES, 'UTF-8'); ?></strong></p>
        <div class="top-links">
            <a class="btn btn-main" href="dashboard.php">Volver al dashboard</a>
            <a class="btn btn-main" href="logout.php">Cerrar sesion</a>
        </div>
    </section>

    <section class="card">
        <h2><?php echo ($accion === "editar" && $usuarioEdicion !== "") ? "Editar usuario" : "Crear usuario"; ?></h2>

        <?php if ($mensaje !== ""): ?>
            <div class="msg"><?php echo htmlspecialchars($mensaje); ?></div>
        <?php endif; ?>

        <?php if ($error !== ""): ?>
            <div class="err"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if ($accion === "editar" && $usuarioEdicion !== ""): ?>
            <form method="POST" action="usuarios.php">
                <input type="hidden" name="tipo" value="editar">
                <input type="hidden" name="usuario_original" value="<?php echo htmlspecialchars($usuarioEdicion); ?>">

                <div class="grid">
                    <div>
                        <label for="usuario">Usuario</label>
                        <input id="usuario" type="text" name="usuario" value="<?php echo htmlspecialchars($usuarioEdicion); ?>" required>
                    </div>
                    <div>
                        <label for="password">Nueva contrasena (opcional)</label>
                        <input id="password" type="password" name="password" placeholder="Dejar vacio para no cambiar">
                    </div>
                </div>

                <div class="top-links">
                    <button class="btn btn-main" type="submit">Guardar cambios</button>
                    <a class="btn btn-main" href="usuarios.php">Cancelar</a>
                </div>
            </form>
        <?php else: ?>
            <form method="POST" action="usuarios.php">
                <input type="hidden" name="tipo" value="crear">

                <div class="grid">
                    <div>
                        <label for="usuario">Usuario</label>
                        <input id="usuario" type="text" name="usuario" required>
                    </div>
                    <div>
                        <label for="password">Contrasena</label>
                        <input id="password" type="password" name="password" required>
                    </div>
                </div>

                <div class="top-links">
                    <button class="btn btn-main" type="submit">Crear usuario</button>
                </div>
            </form>
        <?php endif; ?>
    </section>

    <section class="card">
        <h2>Usuarios registrados</h2>

        <?php if (count($usuarios) === 0): ?>
            <p>No hay usuarios cargados.</p>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>Usuario</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($usuarios as $u): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($u); ?></td>
                            <td class="actions">
                                <a class="btn btn-main" href="usuarios.php?accion=editar&usuario=<?php echo urlencode($u); ?>">Editar</a>
                                <form class="inline tfa-form" method="POST" action="usuarios.php" data-usuario="<?php echo htmlspecialchars($u, ENT_QUOTES, 'UTF-8'); ?>">
                                    <input type="hidden" name="tipo" value="generar_2fa">
                                    <input type="hidden" name="usuario" value="<?php echo htmlspecialchars($u, ENT_QUOTES, 'UTF-8'); ?>">
                                    <button class="btn btn-2fa" type="button" onclick="abrirModal2FA(this)">🔐 2FA</button>
                                </form>
                                <form class="inline" method="POST" action="usuarios.php" onsubmit="return confirm('Seguro que deseas eliminar este usuario?');">
                                    <input type="hidden" name="tipo" value="eliminar">
                                    <input type="hidden" name="usuario" value="<?php echo htmlspecialchars($u); ?>">
                                    <button class="btn btn-danger" type="submit">Eliminar</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </section>

    <?php if ($createResult !== null || $qrDataUri !== ''): ?>
        <section class="card">
            <div class="result-2fa-header">
                <div class="icon-2fa">🔐</div>
                <div>
                    <h2 style="margin-bottom:2px;">Resultado 2FA</h2>
                    <span style="font-size:0.85rem;color:var(--muted);">Autenticación de dos factores</span>
                </div>
            </div>

            <?php if ($mensaje !== ""): ?>
                <div class="msg">✅ <?php echo htmlspecialchars($mensaje); ?></div>
            <?php endif; ?>

            <?php if ($error !== ""): ?>
                <div class="err">⚠️ <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <div class="result-2fa-grid">
                <div>
                    <?php if ($createResult !== null): ?>
                        <p class="output-label">Salida multiOTP</p>
                        <div class="code-block"><?php echo htmlspecialchars(trim($createResult['output'] . "\n" . ($qrResult['output'] ?? '')), ENT_QUOTES, 'UTF-8'); ?></div>
                    <?php endif; ?>
                </div>

                <?php if ($qrDataUri !== ''): ?>
                <div class="qr-container">
                    <p class="qr-label">📱 Escanea con tu app</p>
                    <img src="<?php echo htmlspecialchars($qrDataUri, ENT_QUOTES, 'UTF-8'); ?>" alt="QR 2FA">
                    <p style="font-size:0.78rem;color:var(--muted);margin-top:4px;">Google Authenticator · Microsoft Authenticator · FreeOTP</p>
                </div>
                <?php endif; ?>
            </div>
        </section>
    <?php endif; ?>
</div>

<!-- Modal 2FA personalizado -->
<div class="modal-overlay" id="modal2fa" role="dialog" aria-modal="true" aria-labelledby="modal2faTitle">
    <div class="modal-box">
        <div class="modal-icon">🔐</div>
        <div class="modal-title" id="modal2faTitle">Generar / Regenerar 2FA</div>
        <div class="modal-desc">Se creará o sobreescribirá el token TOTP para el usuario:</div>
        <div style="text-align:center;">
            <span class="modal-user-badge" id="modal2faUser"></span>
        </div>
        <div class="modal-actions">
            <button class="modal-cancel" id="modal2faCancel" onclick="cerrarModal2FA()">Cancelar</button>
            <button class="modal-confirm" id="modal2faConfirm" onclick="confirmarModal2FA()">✅ Confirmar</button>
        </div>
    </div>
</div>

<script>
    let _pendingForm2FA = null;

    function abrirModal2FA(btn) {
        const form = btn.closest('.tfa-form');
        _pendingForm2FA = form;
        const usuario = form.dataset.usuario || '';
        document.getElementById('modal2faUser').textContent = usuario;
        const overlay = document.getElementById('modal2fa');
        overlay.classList.add('active');
        document.getElementById('modal2faConfirm').focus();
    }

    function cerrarModal2FA() {
        const overlay = document.getElementById('modal2fa');
        overlay.classList.remove('active');
        _pendingForm2FA = null;
    }

    function confirmarModal2FA() {
        if (_pendingForm2FA) {
            _pendingForm2FA.submit();
        }
        cerrarModal2FA();
    }

    // Cerrar con Escape o click fuera
    document.getElementById('modal2fa').addEventListener('click', function(e) {
        if (e.target === this) cerrarModal2FA();
    });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') cerrarModal2FA();
    });
</script>
</body>
</html>
