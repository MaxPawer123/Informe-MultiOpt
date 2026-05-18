<?php
require_once __DIR__ . "/multiotp_helper.php";
require_once __DIR__ . "/auditoria.php";

// El modulo bancario tambien queda protegido por el segundo factor.
if (!mfa_require_authenticated($_SESSION)) {
    // Auditoria de intento no autorizado.
    registrarAuditoria($conn, mfa_current_user($_SESSION), 'ACCESO_NO_AUTORIZADO', 'Intento en transferencias.php');
    header('Location: login.php');
    exit();
}
$usuarioSesion = mfa_current_user($_SESSION);

$mensaje = "";
$error = "";

$conn->query("CREATE TABLE IF NOT EXISTS cuentas_bancarias (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cuenta VARCHAR(50) NOT NULL,
    titular VARCHAR(100) NOT NULL,
    saldo DECIMAL(12,2) NOT NULL DEFAULT 0,
    usuario VARCHAR(100) NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_cuenta_usuario (cuenta, usuario)
)");

// Agregar columna usuario si la tabla ya existia sin ella.
$colCheck = $conn->query("SHOW COLUMNS FROM cuentas_bancarias LIKE 'usuario'");
if ($colCheck && $colCheck->num_rows === 0) {
    $conn->query("ALTER TABLE cuentas_bancarias ADD COLUMN usuario VARCHAR(100) NOT NULL DEFAULT '' AFTER saldo");
    // Quitar el UNIQUE original de cuenta si existe, para permitir misma cuenta en distintos usuarios.
    $conn->query("ALTER TABLE cuentas_bancarias DROP INDEX cuenta");
}

$conn->query("CREATE TABLE IF NOT EXISTS transferencias (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cuenta_origen_id INT NOT NULL,
    cuenta_destino_id INT NOT NULL,
    monto DECIMAL(12,2) NOT NULL,
    concepto VARCHAR(255) NOT NULL,
    usuario_sistema VARCHAR(100) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cuenta_origen_id) REFERENCES cuentas_bancarias(id),
    FOREIGN KEY (cuenta_destino_id) REFERENCES cuentas_bancarias(id)
)");

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $tipo = isset($_POST["tipo"]) ? $_POST["tipo"] : "";

    if ($tipo === "crear_cuenta") {
        $cuenta = isset($_POST["cuenta"]) ? trim($_POST["cuenta"]) : "";
        $titular = isset($_POST["titular"]) ? trim($_POST["titular"]) : "";
        $saldoInicial = isset($_POST["saldo_inicial"]) ? (float) $_POST["saldo_inicial"] : 0;
        $otpConfirm = isset($_POST["otp_confirm"]) ? trim($_POST["otp_confirm"]) : "";

        if ($otpConfirm === "") {
            $error = "Debes ingresar tu codigo OTP para confirmar.";
        } elseif (!mfa_validate_otp($usuarioSesion, $otpConfirm)['ok']) {
            $error = "Codigo OTP incorrecto. Operacion cancelada.";
            registrarAuditoria($conn, $usuarioSesion, 'OTP_INCORRECTO', 'OTP incorrecto al crear cuenta');
        } elseif ($cuenta === "" || $titular === "") {
            $error = "Completa los datos de la cuenta.";
        } elseif ($saldoInicial < 0) {
            $error = "El saldo inicial no puede ser negativo.";
        } else {
            $stmt = $conn->prepare("INSERT INTO cuentas_bancarias (cuenta, titular, saldo, usuario) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssds", $cuenta, $titular, $saldoInicial, $usuarioSesion);

            if ($stmt->execute()) {
                $mensaje = "Cuenta agregada correctamente.";
            } else {
                $error = "No se pudo crear la cuenta. Verifica que no exista el mismo numero de cuenta.";
            }
        }
    }

    if ($tipo === "transferir") {
        $origenId = isset($_POST["origen_id"]) ? (int) $_POST["origen_id"] : 0;
        $destinoId = isset($_POST["destino_id"]) ? (int) $_POST["destino_id"] : 0;
        $monto = isset($_POST["monto"]) ? (float) $_POST["monto"] : 0;
        $concepto = isset($_POST["concepto"]) ? trim($_POST["concepto"]) : "Transferencia interna";
        $otpConfirm = isset($_POST["otp_confirm"]) ? trim($_POST["otp_confirm"]) : "";

        if ($otpConfirm === "") {
            $error = "Debes ingresar tu codigo OTP para confirmar la transferencia.";
        } elseif (!mfa_validate_otp($usuarioSesion, $otpConfirm)['ok']) {
            $error = "Codigo OTP incorrecto. Transferencia cancelada.";
            registrarAuditoria($conn, $usuarioSesion, 'OTP_INCORRECTO', 'OTP incorrecto al transferir');
        } elseif ($origenId <= 0 || $destinoId <= 0 || $monto <= 0) {
            $error = "Selecciona cuentas validas e ingresa un monto mayor a cero.";
        } elseif ($origenId === $destinoId) {
            $error = "La cuenta origen y destino deben ser diferentes.";
        } else {
            $conn->begin_transaction();

            try {
                $saldoOrigen = 0;
                $qOrigen = $conn->prepare("SELECT saldo FROM cuentas_bancarias WHERE id = ? AND usuario = ? FOR UPDATE");
                $qOrigen->bind_param("is", $origenId, $usuarioSesion);
                $qOrigen->execute();
                $rOrigen = $qOrigen->get_result();

                if ($rOrigen->num_rows === 0) {
                    throw new Exception("La cuenta de origen no existe o no te pertenece.");
                }

                $saldoOrigen = (float) $rOrigen->fetch_assoc()["saldo"];

                $qDestino = $conn->prepare("SELECT id FROM cuentas_bancarias WHERE id = ? AND usuario = ? FOR UPDATE");
                $qDestino->bind_param("is", $destinoId, $usuarioSesion);
                $qDestino->execute();
                $rDestino = $qDestino->get_result();

                if ($rDestino->num_rows === 0) {
                    throw new Exception("La cuenta de destino no existe o no te pertenece.");
                }

                if ($saldoOrigen < $monto) {
                    throw new Exception("Saldo insuficiente en la cuenta de origen.");
                }

                $u1 = $conn->prepare("UPDATE cuentas_bancarias SET saldo = saldo - ? WHERE id = ?");
                $u1->bind_param("di", $monto, $origenId);
                $u1->execute();

                $u2 = $conn->prepare("UPDATE cuentas_bancarias SET saldo = saldo + ? WHERE id = ?");
                $u2->bind_param("di", $monto, $destinoId);
                $u2->execute();

                $ins = $conn->prepare("INSERT INTO transferencias (cuenta_origen_id, cuenta_destino_id, monto, concepto, usuario_sistema) VALUES (?, ?, ?, ?, ?)");
                $usuarioSistema = $usuarioSesion;
                $ins->bind_param("iidss", $origenId, $destinoId, $monto, $concepto, $usuarioSistema);
                $ins->execute();

                $conn->commit();
                $mensaje = "Transferencia realizada correctamente.";
                // Auditoria de transferencia exitosa.
                $detalleOk = "origen_id={$origenId}; destino_id={$destinoId}; monto={$monto}; concepto={$concepto}";
                registrarAuditoria($conn, $usuarioSesion, 'TRANSFERENCIA_OK', $detalleOk);
            } catch (Exception $e) {
                $conn->rollback();
                $error = $e->getMessage();
                // Auditoria de transferencia con error.
                $detalleErr = "origen_id={$origenId}; destino_id={$destinoId}; monto={$monto}; error={$error}";
                registrarAuditoria($conn, $usuarioSesion, 'TRANSFERENCIA_ERROR', $detalleErr);
            }
        }
    }
}

$cuentas = [];
$qCuentas = $conn->prepare("SELECT id, cuenta, titular, saldo FROM cuentas_bancarias WHERE usuario = ? ORDER BY cuenta ASC");
$qCuentas->bind_param("s", $usuarioSesion);
$qCuentas->execute();
$rCuentas = $qCuentas->get_result();
if ($rCuentas) {
    while ($row = $rCuentas->fetch_assoc()) {
        $cuentas[] = $row;
    }
}

$historial = [];
$sqlHistorial = "SELECT t.id, t.monto, t.concepto, t.usuario_sistema, t.created_at,
                co.cuenta AS cuenta_origen,
                cd.cuenta AS cuenta_destino
                FROM transferencias t
                INNER JOIN cuentas_bancarias co ON t.cuenta_origen_id = co.id
                INNER JOIN cuentas_bancarias cd ON t.cuenta_destino_id = cd.id
                WHERE t.usuario_sistema = ?
                ORDER BY t.id DESC
                LIMIT 100";
$stmtHist = $conn->prepare($sqlHistorial);
$stmtHist->bind_param("s", $usuarioSesion);
$stmtHist->execute();
$qHistorial = $stmtHist->get_result();
if ($qHistorial) {
    while ($row = $qHistorial->fetch_assoc()) {
        $historial[] = $row;
    }
}

// Cargar usuarios del sistema para el select de titular.
$usuariosSistema = [];
$qUsuarios = $conn->query("SELECT usuario FROM usuarios ORDER BY usuario ASC");
if ($qUsuarios) {
    while ($row = $qUsuarios->fetch_assoc()) {
        $usuariosSistema[] = $row['usuario'];
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Modulo de Transferencias</title>
    <style>
        :root {
            --bg: #f3f7fb;
            --card: #ffffff;
            --text: #1b2a41;
            --muted: #5f6c80;
            --accent: #0f766e;
            --accent-dark: #115e59;
            --border: #d9e2ec;
            --ok-bg: #dcfce7;
            --ok-text: #166534;
            --err-bg: #fee2e2;
            --err-text: #991b1b;
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
            max-width: 1050px;
            margin: 0 auto;
            display: grid;
            gap: 16px;
        }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            box-shadow: 0 12px 30px rgba(27, 42, 65, 0.08);
        }

        h1, h2 { margin: 0 0 12px; }

        .hint {
            margin-top: -4px;
            color: var(--muted);
            font-size: 0.92rem;
        }

        .msg, .err {
            padding: 10px 12px;
            border-radius: 10px;
            margin-bottom: 12px;
            font-size: 0.93rem;
        }

        .msg { background: var(--ok-bg); color: var(--ok-text); }
        .err { background: var(--err-bg); color: var(--err-text); }

        .grid {
            display: grid;
            gap: 10px;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        }

        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            font-size: 0.92rem;
        }

        input, select {
            width: 100%;
            padding: 10px 12px;
            border-radius: 10px;
            border: 1px solid var(--border);
            font-size: 0.95rem;
            background: #fff;
        }

        .btn {
            border: none;
            border-radius: 10px;
            padding: 10px 12px;
            color: #fff;
            cursor: pointer;
            font-weight: 700;
            text-decoration: none;
            display: inline-block;
            background: var(--accent);
        }

        .btn:hover { background: var(--accent-dark); }

        .top-links {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 8px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
            font-size: 0.94rem;
        }

        th, td {
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }

        .money { font-weight: 700; }
    </style>
</head>
<body>
<div class="wrap">
    <section class="card">
        <h1>Simulador de transferencias bancarias</h1>
        <p class="hint">Agrega cuentas, transfiere saldo entre ellas y revisa el registro historico.</p>
        <p class="hint">Sesion activa: <strong><?php echo htmlspecialchars($usuarioSesion, ENT_QUOTES, 'UTF-8'); ?></strong></p>
        <div class="top-links">
            <a class="btn" href="dashboard.php">Volver al dashboard</a>
            <a class="btn" href="logout.php">Cerrar sesion</a>
        </div>
    </section>

    <section class="card">
        <h2>Estado del modulo</h2>
        <?php if ($mensaje !== ""): ?>
            <div class="msg"><?php echo htmlspecialchars($mensaje); ?></div>
        <?php endif; ?>
        <?php if ($error !== ""): ?>
            <div class="err"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
    </section>

    <section class="card">
        <h2>Agregar cuenta</h2>
        <form method="POST" action="transferencias.php">
            <input type="hidden" name="tipo" value="crear_cuenta">
            <div class="grid">
                <div>
                    <label for="cuenta">Numero de cuenta</label>
                    <input id="cuenta" name="cuenta" required>
                </div>
                <div>
                    <label for="titular">Titular</label>
                    <select id="titular" name="titular" required>
                        <option value="">Selecciona un usuario</option>
                        <?php foreach ($usuariosSistema as $uSist): ?>
                            <option value="<?php echo htmlspecialchars($uSist, ENT_QUOTES, 'UTF-8'); ?>">
                                <?php echo htmlspecialchars($uSist, ENT_QUOTES, 'UTF-8'); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label for="saldo_inicial">Saldo inicial</label>
                    <input id="saldo_inicial" name="saldo_inicial" type="number" step="0.01" min="0" value="0" required>
                </div>
            </div>
            <div class="top-links">
                <button class="btn btn-otp-action" type="button" data-accion="crear_cuenta">🔒 Crear cuenta</button>
            </div>
        </form>
    </section>

    <section class="card">
        <h2>Realizar transferencia</h2>

        <?php if (count($cuentas) < 2): ?>
            <p>Necesitas al menos 2 cuentas para transferir.</p>
        <?php else: ?>
            <form method="POST" action="transferencias.php">
                <input type="hidden" name="tipo" value="transferir">
                <div class="grid">
                    <div>
                        <label for="origen_id">Cuenta origen</label>
                        <select id="origen_id" name="origen_id" required>
                            <option value="">Selecciona una cuenta</option>
                            <?php foreach ($cuentas as $c): ?>
                                <option value="<?php echo (int) $c["id"]; ?>">
                                    <?php echo htmlspecialchars($c["cuenta"] . " - " . $c["titular"] . " (Saldo: " . number_format((float) $c["saldo"], 2) . ")"); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div>
                        <label for="destino_id">Cuenta destino</label>
                        <select id="destino_id" name="destino_id" required>
                            <option value="">Selecciona una cuenta</option>
                            <?php foreach ($cuentas as $c): ?>
                                <option value="<?php echo (int) $c["id"]; ?>">
                                    <?php echo htmlspecialchars($c["cuenta"] . " - " . $c["titular"]); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div>
                        <label for="monto">Monto</label>
                        <input id="monto" name="monto" type="number" step="0.01" min="0.01" required>
                    </div>
                    <div>
                        <label for="concepto">Concepto</label>
                        <input id="concepto" name="concepto" value="Transferencia interna" required>
                    </div>
                </div>
                <div class="top-links">
                    <button class="btn btn-otp-action" type="button" data-accion="transferir" style="background:linear-gradient(135deg,#f59e0b,#d97706);">🔒 Transferir</button>
                </div>
            </form>
        <?php endif; ?>
    </section>

    <section class="card">
        <h2>Cuentas registradas</h2>
        <?php if (count($cuentas) === 0): ?>
            <p>No hay cuentas cargadas.</p>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Cuenta</th>
                        <th>Titular</th>
                        <th>Saldo</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($cuentas as $c): ?>
                        <tr>
                            <td><?php echo (int) $c["id"]; ?></td>
                            <td><?php echo htmlspecialchars($c["cuenta"]); ?></td>
                            <td><?php echo htmlspecialchars($c["titular"]); ?></td>
                            <td class="money">$ <?php echo number_format((float) $c["saldo"], 2); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </section>

    <section class="card">
        <h2>Historial de transferencias</h2>
        <?php if (count($historial) === 0): ?>
            <p>No hay transferencias registradas.</p>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Origen</th>
                        <th>Destino</th>
                        <th>Monto</th>
                        <th>Concepto</th>
                        <th>Usuario</th>
                        <th>Fecha</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($historial as $t): ?>
                        <tr>
                            <td><?php echo (int) $t["id"]; ?></td>
                            <td><?php echo htmlspecialchars($t["cuenta_origen"]); ?></td>
                            <td><?php echo htmlspecialchars($t["cuenta_destino"]); ?></td>
                            <td class="money">$ <?php echo number_format((float) $t["monto"], 2); ?></td>
                            <td><?php echo htmlspecialchars($t["concepto"]); ?></td>
                            <td><?php echo htmlspecialchars($t["usuario_sistema"]); ?></td>
                            <td><?php echo htmlspecialchars($t["created_at"]); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </section>
</div>

<!-- Modal OTP para confirmar acciones -->
<div class="modal-overlay" id="modalOTP" role="dialog" aria-modal="true">
    <div class="modal-box">
        <div class="modal-icon">🔒</div>
        <div class="modal-title" id="modalOTPTitle">Verificación OTP requerida</div>
        <div class="modal-desc" id="modalOTPDesc">Ingresa tu código OTP para confirmar esta acción.</div>
        <div style="margin:16px 0;">
            <label for="modalOTPInput" style="font-size:0.85rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em;">Código OTP (6 dígitos)</label>
            <input type="text" id="modalOTPInput" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="123456" autocomplete="off" style="text-align:center;letter-spacing:0.4em;font-weight:700;font-size:1.2rem;">
        </div>
        <div id="modalOTPError" style="display:none;background:var(--err-bg);color:var(--err-text);padding:8px 12px;border-radius:10px;font-size:0.85rem;margin-bottom:12px;text-align:center;"></div>
        <div class="modal-actions">
            <button class="modal-cancel" onclick="cerrarModalOTP()">Cancelar</button>
            <button class="modal-confirm" onclick="confirmarModalOTP()">🔑 Confirmar</button>
        </div>
    </div>
</div>

<style>
    .modal-overlay {
        position:fixed;inset:0;background:rgba(15,23,42,0.55);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);
        display:flex;align-items:center;justify-content:center;z-index:9999;
        opacity:0;pointer-events:none;transition:opacity 0.25s ease;
    }
    .modal-overlay.active { opacity:1;pointer-events:all; }
    .modal-box {
        background:#fff;border-radius:22px;padding:32px 28px 24px;max-width:400px;width:90%;
        box-shadow:0 24px 60px rgba(0,0,0,0.2);
        transform:scale(0.88) translateY(20px);transition:transform 0.3s cubic-bezier(0.34,1.56,0.64,1),opacity 0.25s ease;opacity:0;
    }
    .modal-overlay.active .modal-box { transform:scale(1) translateY(0);opacity:1; }
    .modal-icon {
        width:56px;height:56px;background:linear-gradient(135deg,#f59e0b,#d97706);border-radius:16px;
        display:flex;align-items:center;justify-content:center;font-size:1.6rem;margin:0 auto 16px;
    }
    .modal-title { font-size:1.15rem;font-weight:800;color:var(--text);text-align:center;margin-bottom:8px; }
    .modal-desc { font-size:0.9rem;color:var(--muted);text-align:center;margin-bottom:16px;line-height:1.5; }
    .modal-actions { display:flex;gap:10px;justify-content:flex-end; }
    .modal-cancel {
        background:#f1f5f9;color:var(--text);border:none;border-radius:10px;padding:10px 20px;
        font-weight:600;font-size:0.9rem;font-family:inherit;cursor:pointer;transition:background 0.15s;
    }
    .modal-cancel:hover { background:#e2e8f0; }
    .modal-confirm {
        background:linear-gradient(135deg,#f59e0b,#d97706);color:#fff;border:none;border-radius:10px;
        padding:10px 22px;font-weight:700;font-size:0.9rem;font-family:inherit;cursor:pointer;
        transition:opacity 0.15s,transform 0.15s;
    }
    .modal-confirm:hover { opacity:0.9;transform:translateY(-1px); }
</style>

<script>
    let _pendingFormOTP = null;

    function abrirModalOTP(form, accion) {
        _pendingFormOTP = form;
        var desc = document.getElementById('modalOTPDesc');
        var input = document.getElementById('modalOTPInput');
        var errDiv = document.getElementById('modalOTPError');
        errDiv.style.display = 'none';
        input.style.borderColor = 'var(--border)';
        input.value = '';

        if (accion === 'transferir') {
            document.getElementById('modalOTPTitle').textContent = 'Confirmar transferencia';
            desc.textContent = 'Ingresa tu código OTP para autorizar esta transferencia:';
        } else {
            document.getElementById('modalOTPTitle').textContent = 'Confirmar creación de cuenta';
            desc.textContent = 'Ingresa tu código OTP para crear la cuenta bancaria:';
        }

        document.getElementById('modalOTP').classList.add('active');
        setTimeout(function() { input.focus(); }, 150);
    }

    function cerrarModalOTP() {
        document.getElementById('modalOTP').classList.remove('active');
        _pendingFormOTP = null;
    }

    function confirmarModalOTP() {
        var input = document.getElementById('modalOTPInput');
        var otp = input.value.trim();
        var errDiv = document.getElementById('modalOTPError');

        if (otp === '' || !/^\d{6}$/.test(otp)) {
            input.style.borderColor = '#ef4444';
            errDiv.textContent = 'Ingresa un código válido de 6 dígitos.';
            errDiv.style.display = 'block';
            input.focus();
            return;
        }

        if (_pendingFormOTP) {
            var otpField = _pendingFormOTP.querySelector('input[name="otp_confirm"]');
            if (!otpField) {
                otpField = document.createElement('input');
                otpField.type = 'hidden';
                otpField.name = 'otp_confirm';
                _pendingFormOTP.appendChild(otpField);
            }
            otpField.value = otp;
            _pendingFormOTP.submit();
        }
        cerrarModalOTP();
    }

    // Conectar botones
    document.querySelectorAll('.btn-otp-action').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var form = this.closest('form');
            var accion = this.getAttribute('data-accion');
            abrirModalOTP(form, accion);
        });
    });

    // Cerrar con click fuera o Escape
    document.getElementById('modalOTP').addEventListener('click', function(e) {
        if (e.target === this) cerrarModalOTP();
    });
    document.getElementById('modalOTPInput').addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { e.preventDefault(); confirmarModalOTP(); }
    });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') cerrarModalOTP();
    });
</script>
</body>
</html>
