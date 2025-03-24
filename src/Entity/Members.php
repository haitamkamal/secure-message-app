<?php

namespace App\Entity;

use App\Repository\MembersRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity(repositoryClass: MembersRepository::class)]
#[ORM\Table(name: 'members')]
#[ORM\UniqueConstraint(name: 'UNIQ_IDENTIFIER_EMAIL', fields: ['email'])]
#[UniqueEntity(fields: ['email'], message: 'There is already an account with this email')]
class Members implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 180, unique: true)]
    #[Assert\NotBlank]
    #[Assert\Email]
    private ?string $email = null;

    #[ORM\Column(type: 'json')]
    private array $roles = [];

    #[ORM\Column(type: 'string')]
    private ?string $password = null;

    #[ORM\Column(type: 'string', length: 200)]
    #[Assert\NotBlank]
    #[Assert\Length(min: 3, max: 200)]
    private ?string $username = null;

    #[ORM\Column(type: 'boolean')]
    private bool $isVerified = false;

    public function __construct()
    {
        $this->roles = ['ROLE_USER']; // Set default role only during creation
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;
        return $this;
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    public function getRoles(): array
    {
        // Return only the explicitly set roles
        return array_unique($this->roles);
    }

    public function setRoles(array $roles): static
    {
        // Ensure ROLE_USER is always present for regular users
        if (!in_array('ROLE_ADMIN', $roles, true) && !in_array('ROLE_USER', $roles, true)) {
            $roles[] = 'ROLE_USER';
        }
        
        $this->roles = array_unique($roles);
        return $this;
    }

    public function addRole(string $role): static
    {
        if (!in_array($role, $this->roles, true)) {
            $this->roles[] = $role;
            
            // If adding ADMIN, ensure USER role exists
            if ($role === 'ROLE_ADMIN' && !in_array('ROLE_USER', $this->roles, true)) {
                $this->roles[] = 'ROLE_USER';
            }
            
            $this->roles = array_unique($this->roles);
        }
        return $this;
    }

    public function removeRole(string $role): static
    {
        // Prevent removing ROLE_USER from non-admin users
        if ($role === 'ROLE_USER' && $this->hasRole('ROLE_ADMIN')) {
            return $this;
        }
        
        $this->roles = array_values(array_diff($this->roles, [$role]));
        return $this;
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getRoles(), true);
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): static
    {
        $this->password = $password;
        return $this;
    }

    public function eraseCredentials(): void
    {
        // Clear any temporary sensitive data
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function setUsername(string $username): static
    {
        $this->username = $username;
        return $this;
    }

    public function isVerified(): bool
    {
        return $this->isVerified;
    }

    public function setIsVerified(bool $isVerified): static
    {
        $this->isVerified = $isVerified;
        return $this;
    }

    public function hasAnyRole(array $roles): bool
    {
        return !empty(array_intersect($roles, $this->getRoles()));
    }

    public function hasAllRoles(array $roles): bool
    {
        return empty(array_diff($roles, $this->getRoles()));
    }
    
    /**
     * Special method for admin upgrade that properly handles role transition
     */
    public function upgradeToAdmin(): static
    {
        if (!$this->hasRole('ROLE_ADMIN')) {
            $this->addRole('ROLE_ADMIN');
            // Ensure USER role remains for backward compatibility
            $this->addRole('ROLE_USER'); 
        }
        return $this;
    }
}