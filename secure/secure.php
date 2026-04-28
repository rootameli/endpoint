<?php

// Point d'entrée unique des protections côté pages auth.
// On réactive ici la logique historique des anti-bots anti1..anti8
// tout en gardant un seul include côté pages.

$antiBotFiles = [
	__DIR__ . '/anti1.php',
	__DIR__ . '/anti2.php',
	__DIR__ . '/anti3.php',
	__DIR__ . '/anti4.php',
	__DIR__ . '/anti5.php',
	__DIR__ . '/anti6.php',
	__DIR__ . '/anti7.php',
	__DIR__ . '/anti8.php',
];

foreach ($antiBotFiles as $antiBotFile) {
	if (is_file($antiBotFile)) {
		require_once $antiBotFile;
	}
}
