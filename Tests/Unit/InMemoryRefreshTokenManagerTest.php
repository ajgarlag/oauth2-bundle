<?php

declare(strict_types=1);

namespace Trikoder\Bundle\OAuth2Bundle\Tests\Unit;

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use Trikoder\Bundle\OAuth2Bundle\Manager\InMemory\RefreshTokenManager as InMemoryRefreshTokenManager;
use Trikoder\Bundle\OAuth2Bundle\Model\AccessToken;
use Trikoder\Bundle\OAuth2Bundle\Model\Client;
use Trikoder\Bundle\OAuth2Bundle\Model\RefreshToken;

final class InMemoryRefreshTokenManagerTest extends TestCase
{
    private $clock;

    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FrozenClock(new DateTimeImmutable());
    }

    public function testClearExpired(): void
    {
        $inMemoryRefreshTokenManager = new InMemoryRefreshTokenManager($this->clock);

        $testData = $this->buildClearExpiredTestData();

        foreach ($testData['input'] as $token) {
            $inMemoryRefreshTokenManager->save($token);
        }

        $this->assertSame(3, $inMemoryRefreshTokenManager->clearExpired());
        $this->assertManagerContainsExpectedData($testData['output'], $inMemoryRefreshTokenManager);
    }

    private function buildClearExpiredTestData(): array
    {
        $validRefreshTokens = [
            '1111' => $this->buildRefreshToken('1111', '+1 day'),
            '2222' => $this->buildRefreshToken('2222', '+1 hour'),
            '3333' => $this->buildRefreshToken('3333', '+1 second'),
            '4444' => $this->buildRefreshToken('4444', '+0 second'),
        ];

        $expiredRefreshTokens = [
            '5555' => $this->buildRefreshToken('5555', '-1 day'),
            '6666' => $this->buildRefreshToken('6666', '-1 hour'),
            '7777' => $this->buildRefreshToken('7777', '-1 second'),
        ];

        return [
            'input' => $validRefreshTokens + $expiredRefreshTokens,
            'output' => $validRefreshTokens,
        ];
    }

    public function testClearRevoked(): void
    {
        $inMemoryRefreshTokenManager = new InMemoryRefreshTokenManager($this->clock);

        $testData = $this->buildClearRevokedTestData();

        foreach ($testData['input'] as $token) {
            $inMemoryRefreshTokenManager->save($token);
        }

        $this->assertSame(2, $inMemoryRefreshTokenManager->clearRevoked());
        $this->assertManagerContainsExpectedData($testData['output'], $inMemoryRefreshTokenManager);
    }

    private function buildClearRevokedTestData(): array
    {
        $validRefreshTokens = [
            '1111' => $this->buildRefreshToken('1111', '+1 day'),
            '2222' => $this->buildRefreshToken('2222', '+1 hour'),
            '3333' => $this->buildRefreshToken('3333', '+1 second'),
        ];

        $revokedRefreshTokens = [
            '5555' => $this->buildRefreshToken('5555', '-1 day', true),
            '6666' => $this->buildRefreshToken('6666', '-1 hour', true),
        ];

        return [
            'input' => $validRefreshTokens + $revokedRefreshTokens,
            'output' => $validRefreshTokens,
        ];
    }

    private function buildRefreshToken(string $identifier, string $modify, bool $revoked = false): RefreshToken
    {
        $expiry = $this->clock->now()->modify($modify);
        $refreshToken = new RefreshToken(
            $identifier,
            $expiry,
            new AccessToken(
                $identifier,
                $this->clock->now()->modify('+1 day'),
                new Client('client', 'secret'),
                null,
                []
            )
        );

        if ($revoked) {
            $refreshToken->revoke();
        }

        return $refreshToken;
    }

    private function assertManagerContainsExpectedData(array $output, InMemoryRefreshTokenManager $inMemoryRefreshTokenManager): void
    {
        $reflectionProperty = new ReflectionProperty(InMemoryRefreshTokenManager::class, 'refreshTokens');
        $reflectionProperty->setAccessible(true);

        $this->assertSame($output, $reflectionProperty->getValue($inMemoryRefreshTokenManager));
    }
}
