<?php

declare(strict_types=1);

$dataFile = __DIR__ . '/data.json';
$config = [];

if (file_exists($dataFile)) {
    $config = json_decode(file_get_contents($dataFile), true) ?? [];
}

function flattenData($data, string $prefix = ''): array
{
    $result = [];

    if (is_array($data)) {
        foreach ($data as $key => $value) {
            $newKey = $prefix === ''
                ? (string)$key
                : $prefix . '.' . $key;

            if (is_array($value)) {
                $result += flattenData($value, $newKey);
            } else {
                $result[$newKey] = (string)$value;
            }
        }
    }

    return $result;
}

function collectValues($data): array
{
    $values = [];

    if (is_array($data)) {
        foreach ($data as $value) {
            if (is_array($value)) {
                $values = array_merge($values, collectValues($value));
            } else {
                $values[] = (string)$value;
            }
        }
    }

    return $values;
}

function findEmails(array $values): array
{
    $result = [];

    foreach ($values as $value) {
        preg_match_all(
            '/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/',
            $value,
            $matches
        );

        foreach ($matches[0] as $mail) {
            $result[] = strtolower($mail);
        }
    }

    return array_values(array_unique($result));
}

function findIPs(array $values): array
{
    $result = [];

    foreach ($values as $value) {
        preg_match_all(
            '/\b(?:\d{1,3}\.){3}\d{1,3}\b/',
            $value,
            $matches
        );

        foreach ($matches[0] as $ip) {
            $result[] = $ip;
        }
    }

    return array_values(array_unique($result));
}

function findDomains(array $values): array
{
    $domains = [];

    foreach ($values as $value) {
        preg_match_all(
            '/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i',
            $value,
            $matches
        );

        foreach ($matches[0] as $domain) {
            $domains[] = strtolower($domain);
        }
    }

    return array_values(array_unique($domains));
}

function getInterestingFields(array $flat, array $keywords): array
{
    $result = [];

    foreach ($flat as $key => $value) {

        foreach ($keywords as $keyword) {

            if (stripos($key, $keyword) !== false) {

                $result[$key] = $value;
                break;
            }
        }
    }

    return $result;
}

function calculateRisk(
    array $flat,
    array $allValues,
    array $rules
): array {

    $score = 0;
    $findings = [];

    foreach ($rules as $rule) {

        $matched = false;

        foreach ($flat as $key => $value) {

            foreach (($rule['match'] ?? []) as $pattern) {

                if (
                    stripos($key, $pattern) !== false ||
                    stripos((string)$value, $pattern) !== false
                ) {
                    $matched = true;
                    break 2;
                }
            }
        }

        if ($matched) {

            $score += (int)($rule['score'] ?? 0);

            $findings[] = [
                'title' => $rule['title'] ?? '',
                'description' => $rule['description'] ?? ''
            ];
        }
    }

    if ($score >= 80) {
        $severity = 'Kritisch';
    } elseif ($score >= 50) {
        $severity = 'Hoch';
    } elseif ($score >= 20) {
        $severity = 'Mittel';
    } else {
        $severity = 'Niedrig';
    }

    return [
        'score' => $score,
        'severity' => $severity,
        'findings' => $findings
    ];
}

$result = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    try {

        $input = trim($_POST['log'] ?? '');

        if ($input === '') {
            throw new RuntimeException('Kein Log übergeben.');
        }

        $json = json_decode($input, true);

        if (!is_array($json)) {
            throw new RuntimeException('Ungültiges JSON.');
        }

        $flat = flattenData($json);

        $allValues = collectValues($json);

        $emails = findEmails($allValues);
        $ips = findIPs($allValues);
        $domains = findDomains($allValues);

        $timestampFields = getInterestingFields(
            $flat,
            ['timestamp', 'time', 'creationtime']
        );

        $actionFields = getInterestingFields(
            $flat,
            [
                'action',
                'operation',
                'event',
                'activity'
            ]
        );

        $userFields = getInterestingFields(
            $flat,
            [
                'user',
                'upn',
                'account',
                'identity',
                'actor'
            ]
        );

        $tenantFields = getInterestingFields(
            $flat,
            [
                'tenant',
                'organization'
            ]
        );

        $risk = calculateRisk(
            $flat,
            $allValues,
            $config['rules'] ?? []
        );

        $result = [
            'emails' => $emails,
            'ips' => $ips,
            'domains' => $domains,
            'timestamps' => $timestampFields,
            'actions' => $actionFields,
            'users' => $userFields,
            'tenants' => $tenantFields,
            'risk' => $risk,
            'flat' => $flat
        ];

    } catch (Throwable $e) {

        $error = $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>IDR Investigation Analyzer</title>

<style>
body{
    font-family:Arial,sans-serif;
    margin:30px;
    background:#fff;
    color:#222;
}

h1{
    margin-bottom:5px;
}

textarea{
    width:100%;
    height:260px;
}

button{
    margin-top:10px;
    padding:10px 20px;
}

.section{
    margin-top:25px;
}

.box{
    border:1px solid #ddd;
    padding:15px;
    margin-top:10px;
    border-radius:4px;
}

.severity-niedrig{
    color:#2e7d32;
}

.severity-mittel{
    color:#ef6c00;
}

.severity-hoch{
    color:#d84315;
}

.severity-kritisch{
    color:#c62828;
    font-weight:bold;
}

ul{
    margin:0;
}
</style>
</head>
<body>

<h1>IDR Investigation Analyzer</h1>

<form method="post">

<textarea
name="log"
placeholder="Rapid7 JSON einfügen"><?=
htmlspecialchars($_POST['log'] ?? '')
?></textarea>

<br>

<button type="submit">
Analysieren
</button>

</form>

<?php if ($error): ?>

<div class="section box">
<?= htmlspecialchars($error) ?>
</div>

<?php endif; ?>

<?php if ($result): ?>

<div class="section">
<h2>Zusammenfassung</h2>

<div class="box">

<?php
$class = 'severity-' . strtolower($result['risk']['severity']);
?>

<p>
<strong>Risiko:</strong>
<span class="<?= $class ?>">
<?= htmlspecialchars($result['risk']['severity']) ?>
(<?= $result['risk']['score'] ?>)
</span>
</p>

<p>
<strong>E-Mails:</strong>
<?= count($result['emails']) ?>
</p>

<p>
<strong>IPs:</strong>
<?= count($result['ips']) ?>
</p>

<p>
<strong>Domains:</strong>
<?= count($result['domains']) ?>
</p>

</div>
</div>

<div class="section">
<h2>Erkannte Aktionen</h2>

<div class="box">
<ul>
<?php foreach ($result['actions'] as $k=>$v): ?>
<li>
<strong><?= htmlspecialchars($k) ?>:</strong>
<?= htmlspecialchars($v) ?>
</li>
<?php endforeach; ?>
</ul>
</div>
</div>

<div class="section">
<h2>Benutzer / Accounts</h2>

<div class="box">
<ul>
<?php foreach ($result['users'] as $k=>$v): ?>
<li>
<strong><?= htmlspecialchars($k) ?>:</strong>
<?= htmlspecialchars($v) ?>
</li>
<?php endforeach; ?>
</ul>
</div>
</div>

<div class="section">
<h2>Indikatoren</h2>

<div class="box">

<p>
<strong>E-Mails</strong><br>
<?= htmlspecialchars(implode(', ', $result['emails'])) ?>
</p>

<p>
<strong>IPs</strong><br>
<?= htmlspecialchars(implode(', ', $result['ips'])) ?>
</p>

<p>
<strong>Domains</strong><br>
<?= htmlspecialchars(implode(', ', $result['domains'])) ?>
</p>

</div>
</div>

<div class="section">
<h2>Bewertung</h2>

<div class="box">

<?php if (empty($result['risk']['findings'])): ?>

Keine spezifischen Auffälligkeiten erkannt.

<?php else: ?>

<ul>
<?php foreach ($result['risk']['findings'] as $finding): ?>
<li>
<strong><?= htmlspecialchars($finding['title']) ?></strong><br>
<?= htmlspecialchars($finding['description']) ?>
</li>
<?php endforeach; ?>
</ul>

<?php endif; ?>

</div>
</div>

<?php endif; ?>

</body>
</html>
