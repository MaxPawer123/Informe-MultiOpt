<?php
require_once __DIR__ . '/app1/multiotp_helper.php';

header('Content-Type: application/json; charset=utf-8');

$user = isset($_REQUEST['user']) ? trim((string) $_REQUEST['user']) : '';
$otp = isset($_REQUEST['otp']) ? trim((string) $_REQUEST['otp']) : '';

if ($user === '' || $otp === '') {
	http_response_code(400);
	echo json_encode([
		'ok' => false,
		'code' => 400,
		'message' => 'Parametros incompletos: user y otp son requeridos.'
	]);
	exit;
}

$multiotpPath = MULTIOTP_EXE;
if (!file_exists($multiotpPath)) {
	http_response_code(500);
	echo json_encode([
		'ok' => false,
		'code' => 500,
		'message' => 'No se encontro multiotp.exe en el servidor.'
	]);
	exit;
}

$result = mfa_validate_otp($user, $otp);

echo json_encode([
	'ok' => $result['ok'],
	'code' => $result['exit_code'],
	'message' => $result['ok'] ? 'OTP valido' : 'OTP invalido o error de validacion',
	'raw' => $result['output']
]);
?>