<?php
session_start();
require_once __DIR__ . "/multiotp_helper.php";
require_once __DIR__ . "/auditoria.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $usuario = isset($_POST["usuario"]) ? trim($_POST["usuario"]) : "";
    $passwordPlano = isset($_POST["password"]) ? $_POST["password"] : "";

    if ($usuario === "" || $passwordPlano === "") {
        // Auditoria de intento de login incompleto.
        registrarAuditoria($conn, $usuario, 'LOGIN_FALLIDO', 'Campos vacios');
        header("Location: login.php?error=2");
        exit();
    }

    $password = sha1($passwordPlano);

    $stmt = $conn->prepare("SELECT * FROM usuarios WHERE usuario = ? AND password = ?");
    $stmt->bind_param("ss", $usuario, $password);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        if (!mfa_multiotp_available()) {
            // Auditoria de error de MFA.
            registrarAuditoria($conn, $usuario, 'ERROR_IMPORTANTE', 'multiOTP no disponible');
            header("Location: login.php?error=3");
            exit();
        }

        // Solo guardamos una sesion temporal para pasar al segundo factor.
        mfa_start_pending_session($_SESSION, $usuario);
        // Auditoria de login exitoso (pendiente OTP).
        registrarAuditoria($conn, $usuario, 'LOGIN_EXITOSO', 'Credenciales correctas, pendiente OTP');
        header("Location: verify_otp.php");
        exit();
    }

    // Auditoria de credenciales invalidas.
    registrarAuditoria($conn, $usuario, 'LOGIN_FALLIDO', 'Credenciales invalidas');
    header("Location: login.php?error=1");
    exit();
}

header("Location: login.php");
exit();
?>
