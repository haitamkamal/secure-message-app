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
        // If the user is already logged in, redirect based on role
        if ($this->getUser()) {
            // Log session and cookie details
            $this->logger->info('User logged in', [
                'username' => $this->getUser()->getUsername(),
                'session_id' => $request->getSession()->getId(),
                'remember_me_cookie' => $request->cookies->get('remember_me'),
            ]);

            // Redirect based on the user's role
            if ($this->isGranted('ROLE_ADMIN')) {
                return $this->redirectToRoute('app_admin');
            } else {
                return $this->redirectToRoute('app_user');
            }
        }

        // Get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // Last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        // Render the login form if the user is not logged in
        return $this->render('login/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    #[Route(path: '/login_check', name: 'login_check')]
    public function check(): void
    {
        // This method will never be executed
        throw new \LogicException('This method should not be called directly.');
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