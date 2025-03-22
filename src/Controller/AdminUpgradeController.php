<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Doctrine\ORM\EntityManagerInterface;
use App\Entity\User;

class AdminUpgradeController extends AbstractController
{
    #[Route('/upgrade', name: 'upgrade_to_admin', methods: ['GET', 'POST'])]
    public function upgradeToAdmin(Request $request, EntityManagerInterface $entityManager): Response
    {
        $user = $this->getUser(); // Symfony still provides this helper function, but it's less tied to the Security component
        
        if (!$user) {
            // If there's no logged-in user, return an error or redirect.
            $this->addFlash('error', 'You need to be logged in to upgrade your role.');
            return $this->redirectToRoute('app_login');
        }

        $adminPassword = $request->request->get('admin_password');

        if ($request->getMethod() === 'POST') {
            if ($adminPassword === 'admin123') {
                if (!in_array('ROLE_ADMIN', $user->getRoles(), true)) {
                    // Add ROLE_ADMIN to the current user
                    $roles = $user->getRoles();
                    $roles[] = 'ROLE_ADMIN'; // Add the new role
                    $user->setRoles($roles);
                    $entityManager->flush();
                    $this->addFlash('success', 'You are now an admin!');
                } else {
                    $this->addFlash('info', 'You are already an admin.');
                }
            } else {
                $this->addFlash('error', 'Incorrect admin password.');
            }

            // Redirect based on role after POST
            if (in_array('ROLE_ADMIN', $user->getRoles(), true)) {
                return $this->redirectToRoute('app_admin');
            } else {
                return $this->redirectToRoute('app_user');
            }
        }

        // Render the form when the method is GET
        return $this->render('upgrade\index.html.twig');
    }
}
