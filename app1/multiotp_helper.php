<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/conexion.php';

define('MULTIOTP_EXE', 'C:\\laragon\\www\\multiotp\\windows\\multiotp.exe');

function mfa_multiotp_available()
{
    return is_file(MULTIOTP_EXE) && is_readable(MULTIOTP_EXE);
}

function mfa_username_normalize($username)
{
    return trim((string) $username);
}

function mfa_current_user(array $session)
{
    if (isset($session['mfa_authenticated']) && $session['mfa_authenticated'] === true && !empty($session['mfa_user'])) {
        return (string) $session['mfa_user'];
    }

    if (!empty($session['mfa_pending_user'])) {
        return (string) $session['mfa_pending_user'];
    }

    return '';
}

function mfa_is_authenticated(array $session)
{
    return isset($session['mfa_authenticated']) && $session['mfa_authenticated'] === true && !empty($session['mfa_user']);
}

function mfa_require_authenticated(array $session)
{
    return mfa_is_authenticated($session);
}

function mfa_require_pending_or_authenticated(array $session)
{
    return mfa_is_authenticated($session) || !empty($session['mfa_pending_user']);
}

function mfa_start_pending_session(array &$session, $username)
{
    session_regenerate_id(true);
    $session['mfa_pending_user'] = mfa_username_normalize($username);
    $session['mfa_pending_started_at'] = time();
    unset($session['mfa_authenticated'], $session['mfa_user'], $session['mfa_authenticated_at']);
}

function mfa_finish_session(array &$session, $username)
{
    session_regenerate_id(true);
    $session['mfa_authenticated'] = true;
    $session['mfa_user'] = mfa_username_normalize($username);
    $session['mfa_authenticated_at'] = time();
    unset($session['mfa_pending_user'], $session['mfa_pending_started_at']);
}

function mfa_clear_session(array &$session)
{
    unset(
        $session['mfa_pending_user'],
        $session['mfa_pending_started_at'],
        $session['mfa_authenticated'],
        $session['mfa_user'],
        $session['mfa_authenticated_at']
    );
}

function mfa_run_multiotp(array $arguments)
{
    if (!mfa_multiotp_available()) {
        return [
            'ok' => false,
            'exit_code' => 500,
            'output' => 'No se encontro multiOTP en la ruta configurada.',
            'command' => '',
        ];
    }

    $command = escapeshellarg(MULTIOTP_EXE);
    foreach ($arguments as $argument) {
        $command .= ' ' . escapeshellarg((string) $argument);
    }

    $output = [];
    $exitCode = 1;
    exec($command . ' 2>&1', $output, $exitCode);

    return [
        'ok' => ($exitCode === 0),
        'exit_code' => $exitCode,
        'output' => trim(implode("\n", $output)),
        'command' => $command,
    ];
}

function mfa_validate_otp($username, $otp)
{
    $username = mfa_username_normalize($username);
    $otp = trim((string) $otp);

    $attempt = mfa_run_multiotp(['-check', $username, $otp]);
    if ($attempt['ok']) {
        return $attempt;
    }

    if ($attempt['exit_code'] === 30 || $attempt['exit_code'] === 99 || stripos($attempt['output'], 'missing') !== false) {
        return mfa_run_multiotp([$username, $otp]);
    }

    return $attempt;
}

function mfa_create_token_and_qr($username)
{
    $username = mfa_username_normalize($username);

    $createResult = mfa_run_multiotp(['-fastcreatenopin', $username]);
    $acceptableCodes = [0, 11, 16, 17, 19, 22];
    $createdOk = in_array($createResult['exit_code'], $acceptableCodes, true);

    $qrPath = rtrim(sys_get_temp_dir(), "\\/") . DIRECTORY_SEPARATOR . 'multiotp_' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $username) . '.png';
    if (is_file($qrPath)) {
        unlink($qrPath);
    }

    $qrResult = mfa_run_multiotp(['-qrcode', $username, $qrPath]);
    $qrExists = is_file($qrPath) && filesize($qrPath) > 0;

    $base64Qr = '';
    if ($qrExists) {
        $qrBinary = file_get_contents($qrPath);
        if ($qrBinary !== false) {
            $base64Qr = 'data:image/png;base64,' . base64_encode($qrBinary);
        }
    }

    return [
        'ok' => $createdOk,
        'create_result' => $createResult,
        'qr_result' => $qrResult,
        'qr_path' => $qrPath,
        'qr_data_uri' => $base64Qr,
    ];
}
