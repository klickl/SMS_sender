<?php
require_once(dirname(__FILE__) . '/function.php');

if(isset($_POST['action']) && $_POST['action'] == "valider")
{

    if((isset($_POST['destinataire']) && $_POST['destinataire'] != "") && (isset($_POST['contenu']) && $_POST['contenu'] != ""))
    {
        $destination = $_POST['destinataire'];
        $message = $_POST['contenu'];
        sendSms($message, $destination);
        header("Location: index.php?message=sent");
    }

    else{
        header("Location: index.php?message=error-fill");
    }
}


