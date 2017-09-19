<?php 
	require_once(dirname(__FILE__) . '/function.php');
	$credits = getCredits();
?>
<!DOCTYPE html>

<html>
	<head>
		<title>Envoie sms</title>
	</head>


	<body>
		<h1>
			Envoyez un sms !
		</h1>


		<div>
			<form action="sms_sender.php" method="POST">

				<?php 
					if (isset($_GET['message']))
					{
						if($_GET['message'] == 'error-fill')
						{
							echo "Vous devez saisir un numéro et un mot de passe";
						}

					}
				?>

				<div>
					Nombre de crédits: <?= $credits ?>
				</div>

				<label>Numéro du destinataire</label>
				<br>
				<input type="text" name="destinataire" />
				
				<br>
				<br>

				<label>Contenu du message</label>
				<br>
				<textarea name="contenu"></textarea>
				
				<br>
				<br>

				<input type="submit" value="valider" name="action"/>
			</form>
		</div>

	</body>
</html>
