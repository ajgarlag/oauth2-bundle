<?php

declare(strict_types=1);

namespace Trikoder\Bundle\OAuth2Bundle\Manager\Doctrine;

use Doctrine\ORM\EntityManagerInterface;
use Lcobucci\Clock\Clock;
use Trikoder\Bundle\OAuth2Bundle\Manager\AccessTokenManagerInterface;
use Trikoder\Bundle\OAuth2Bundle\Model\AccessToken;

final class AccessTokenManager implements AccessTokenManagerInterface
{
    /**
     * @var EntityManagerInterface
     */
    private $entityManager;

    /**
     * @var Clock
     */
    private $clock;

    public function __construct(EntityManagerInterface $entityManager, Clock $clock)
    {
        $this->entityManager = $entityManager;
        $this->clock = $clock;
    }

    /**
     * {@inheritdoc}
     */
    public function find(string $identifier): ?AccessToken
    {
        return $this->entityManager->find(AccessToken::class, $identifier);
    }

    /**
     * {@inheritdoc}
     */
    public function save(AccessToken $accessToken): void
    {
        $this->entityManager->persist($accessToken);
        $this->entityManager->flush();
    }

    public function clearExpired(): int
    {
        return $this->entityManager->createQueryBuilder()
            ->delete(AccessToken::class, 'at')
            ->where('at.expiry < :expiry')
            ->setParameter('expiry', $this->clock->now())
            ->getQuery()
            ->execute();
    }

    public function clearRevoked(): int
    {
        return $this->entityManager->createQueryBuilder()
            ->delete(AccessToken::class, 'at')
            ->where('at.revoked = true')
            ->getQuery()
            ->execute();
    }
}
