<?php

function full_name($user) {
	if (isset($user->name)) {
		return $user->name;
	}
	$name = [];
	if (isset($user->given_name)) {
		$name[] = $user->given_name;
	}
	if (isset($user->family_name)) {
		$name[] = $user->family_name;
	}
	return implode(' ', $name);
}

function connected($provider, $user, $logout = '') {
	?>
	<!DOCTYPE html>
	<html>
		<head>
			<title><?php echo htmlspecialchars($provider.' client results'); ?></title>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
			<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
			<link href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css" rel="stylesheet" integrity="sha384-wvfXpqpZZVQGK6TAh5PVlGOfQNHSoD2xbE+QkPxCAFlNEevoEH3Sl0sibVcOQVnN" crossorigin="anonymous">
		</head>
		<body>
			<div class="container">
				<h1>
				<?php echo htmlspecialchars(full_name($user)),
				', you have logged in successfully with '.$provider.'!'; ?>
				</h1>
				<table class="table">
					<thead>
						<tr>
							<th scope="col">Field</th>
							<th scope="col">Value</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ($user as $field => $value) { ?>
						<tr>
							<th scope="row"><?php echo ucfirst(str_replace('_', ' ', $field)); ?></th>
							<td><?php echo is_object($value) ? '<pre>'.json_encode($value, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT).'</pre>' : $value; ?></td>
						</tr>
						<?php } ?>
					</tbody>
				</table>
				<?php if (!empty($logout)) { ?>
				<div>
					<a href="<?php echo $logout; ?>">disconnect from <?php echo $provider; ?></a>
				</div>
				<?php } ?>
			</div>
		</body>
	</html>
	<?php
}

function failed($title, $message) {
	?>
	<!DOCTYPE html>
	<html>
		<head>
			<title><?php echo htmlspecialchars($title); ?></title>
		</head>
		<body>
			<h1><?php echo htmlspecialchars($title); ?></h1>
			<pre>Error: <?php echo htmlspecialchars($message); ?></pre>
		</body>
	</html>
	<?php
}
?>
