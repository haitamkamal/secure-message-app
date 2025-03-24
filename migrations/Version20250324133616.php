<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20250324133616 extends AbstractMigration
{
public function up(Schema $schema): void
{
    // Option 1: Allow NULL values initially
    $this->addSql('ALTER TABLE members ADD is_verified BOOLEAN DEFAULT NULL');
    
    // Option 2: Set all existing records to false
    $this->addSql('ALTER TABLE members ADD is_verified BOOLEAN DEFAULT false NOT NULL');
    
    // If you used Option 1, add this to update existing records:
    $this->addSql('UPDATE members SET is_verified = false WHERE is_verified IS NULL');
    
    // Then add the NOT NULL constraint if needed
    $this->addSql('ALTER TABLE members ALTER COLUMN is_verified SET NOT NULL');
}

public function down(Schema $schema): void
{
    $this->addSql('ALTER TABLE members DROP is_verified');
}
}
