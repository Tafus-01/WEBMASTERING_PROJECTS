<?php 
    session_start(); // Démarrage de la session
    require_once 'config.php'; // On inclut la connexion à la base de données

    if(!empty($_POST['emailadmin']) && !empty($_POST['passwordadmin'])) // Si il existe les champs email, password et qu'il sont pas vident
    {
        // Patch XSS
        $emailadmin = htmlspecialchars($_POST['emailadmin']); 
        $passwordadmin = htmlspecialchars($_POST['passwordadmin']);
        
        $emailadmin = strtolower($emailadmin); // email transformé en minuscule
        
        // On regarde si l'utilisateur est inscrit dans la table utilisateurs
        $check = $bdd->prepare('SELECT pseudoadmin, emailadmin, passwordadmin, tokenadmin FROM utilisateursadmin WHERE emailadmin = ?');
        $check->execute(array($emailadmin));
        $data = $check->fetch();
        $row = $check->rowCount();
        
        

        // Si > à 0 alors l'utilisateur existe
        if($row > 0)
        {
            // Si le mail est bon niveau format
            if(filter_var($emailadmin, FILTER_VALIDATE_EMAIL))
            {
                // Si le mot de passe est le bon
                if(password_verify($passwordadmin, $data['password']))
                {
                    // On créer la session et on redirige sur landing.php
                    $_SESSION['user'] = $data['token'];
                    header('Location: landing.php');
                    die();
                }else{ header('Location: index.php?login_err=password'); die(); }
            }else{ header('Location: index.php?login_err=email'); die(); }
        }else{ header('Location: index.php?login_err=already'); die(); }
    }else{ header('Location: index.php'); die();} // si le formulaire est envoyé sans aucune données