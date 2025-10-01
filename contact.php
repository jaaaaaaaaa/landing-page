<?php

header('Content-Type: application/json');

$response = ['status' => 'success', 'message' => 'Thank you for submitting the form!'];
echo json_encode($response);