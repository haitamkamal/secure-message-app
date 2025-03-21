<?php
// src/Controller/LoginController.php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Psr\Log\LoggerInterface;

class LoginController extends AbstractController
{
    private $logger;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    #[Route(path: '/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils, Request $request): Response
    {
        // Get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // Last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        // If the user is already authenticated, redirect them
        if ($this->getUser()) {
            // Log session and cookie details
            $this->logger->info('User logged in', [
                'username' => $this->getUser()->getUsername(),
                'session_id' => $request->getSession()->getId(),
                'remember_me_cookie' => $request->cookies->get('remember_me'),
            ]);

            // Redirect to a specific route after login
            return $this->redirectToRoute('app_user');
        }

        return $this->render('login/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    #[Route(path: '/logout', name: 'app_logout')]
    public function logout(Request $request): Response
    {
        // Log session and cookie details before clearing
        $this->logger->info('User logging out', [
            'session_id' => $request->getSession()->getId(),
            'remember_me_cookie' => $request->cookies->get('remember_me'),
        ]);

        // Clear the session
        $session = $request->getSession();
        $session->invalidate();

        // Clear the remember me cookie
        $response = new Response();
        $response->headers->clearCookie('remember_me');

        // Redirect to the homepage or login page
        return $this->redirectToRoute('app_login', [], Response::HTTP_SEE_OTHER, $response);
    }
}