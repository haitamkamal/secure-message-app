<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RateLimiter\RequestRateLimiterInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

class AdminUpgradeController extends AbstractController
{
    public function __construct(
        private LoggerInterface $logger,
        private UserPasswordHasherInterface $passwordHasher
    ) {
    }

    #[Route('/upgrade', name: 'upgrade_to_admin', methods: ['GET', 'POST'])]
    public function upgradeToAdmin(
        Request $request,
        EntityManagerInterface $entityManager,
        TokenStorageInterface $tokenStorage
    ): Response {
        $user = $this->getUser();
        
        if (!$user) {
            $this->addFlash('error', 'You need to be logged in to upgrade your role.');
            return $this->redirectToRoute('app_login');
        }

        // Rate limiting check (implement your own rate limiting logic)
        if ($this->isTooManyAttempts($request)) {
            $this->addFlash('error', 'Too many attempts. Please try again later.');
            return $this->redirectToRoute('app_user');
        }

        if ($request->isMethod('POST')) {
            $adminPassword = $request->request->get('admin_password');
            
            if (!$adminPassword) {
                $this->addFlash('error', 'Please enter the admin password.');
                return $this->redirectToRoute('upgrade_to_admin');
            }

            // In production, use proper password verification
            $isValidPassword = $this->verifyAdminPassword($adminPassword);
            
            if ($isValidPassword) {
                if (!$user->hasRole('ROLE_ADMIN')) {
                    $user->addRole('ROLE_ADMIN');
                    
                    try {
                        $entityManager->flush();
                        
                        // Refresh authentication
                        $token = new UsernamePasswordToken(
                            $user,
                            'main',
                            $user->getRoles()
                        );
                        $tokenStorage->setToken($token);
                        
                        $this->logger->info('User role upgraded to admin', [
                            'user_id' => $user->getId(),
                            'email' => $user->getEmail()
                        ]);
                        
                        $this->addFlash('success', 'You are now an admin!');
                        return $this->redirectToRoute('app_admin');
                    } catch (\Exception $e) {
                        $this->logger->error('Role upgrade failed', [
                            'error' => $e->getMessage(),
                            'user_id' => $user->getId()
                        ]);
                        $this->addFlash('error', 'An error occurred during role upgrade.');
                    }
                } else {
                    $this->addFlash('info', 'You are already an admin.');
                    return $this->redirectToRoute('app_admin');
                }
            } else {
                $this->logger->warning('Failed admin upgrade attempt', [
                    'user_id' => $user->getId(),
                    'ip' => $request->getClientIp()
                ]);
                $this->addFlash('error', 'Incorrect admin password.');
            }
        }

        return $this->render('upgrade/index.html.twig');
    }

    private function verifyAdminPassword(string $password): bool
    {
        // In production, use one of these:
        // 1. Compare against hashed password from configuration
        // 2. Use UserPasswordHasherInterface to verify
        // 3. Check against secret stored in environment variables
        
        // Temporary implementation (replace this!)
        return $password === 'admin123';
    }

    private function isTooManyAttempts(Request $request): bool
    {
        // Implement your rate limiting logic here
        // Example: Check session for attempt count
        $session = $request->getSession();
        $attempts = $session->get('upgrade_attempts', 0);
        
        if ($attempts >= 5) {
            return true;
        }
        
        $session->set('upgrade_attempts', $attempts + 1);
        return false;
    }
}