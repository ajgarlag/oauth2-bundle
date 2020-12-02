<?php

declare(strict_types=1);

namespace Trikoder\Bundle\OAuth2Bundle\Tests\Unit;

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use Trikoder\Bundle\OAuth2Bundle\Manager\InMemory\AuthorizationCodeManager as InMemoryAuthCodeManager;
use Trikoder\Bundle\OAuth2Bundle\Model\AuthorizationCode;
use Trikoder\Bundle\OAuth2Bundle\Model\Client;

final class InMemoryAuthCodeManagerTest extends TestCase
{
    private $clock;

    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FrozenClock(new DateTimeImmutable());
    }

    public function testClearExpired(): void
    {
        $inMemoryAuthCodeManager = new InMemoryAuthCodeManager($this->clock);

        $testData = $this->buildClearExpiredTestData();

        foreach ($testData['input'] as $token) {
            $inMemoryAuthCodeManager->save($token);
        }

        $this->assertSame(3, $inMemoryAuthCodeManager->clearExpired());
        $this->assertManagerContainsExpectedData($testData['output'], $inMemoryAuthCodeManager);
    }

    private function buildClearExpiredTestData(): array
    {
        $validAuthCodes = [
            '1111' => $this->buildAuthCode('1111', '+1 day'),
            '2222' => $this->buildAuthCode('2222', '+1 hour'),
            '3333' => $this->buildAuthCode('3333', '+1 second'),
            '4444' => $this->buildAuthCode('4444', '+0 second'),
        ];

        $expiredAuthCodes = [
            '5555' => $this->buildAuthCode('5555', '-1 day'),
            '6666' => $this->buildAuthCode('6666', '-1 hour'),
            '7777' => $this->buildAuthCode('7777', '-1 second'),
        ];

        return [
            'input' => $validAuthCodes + $expiredAuthCodes,
            'output' => $validAuthCodes,
        ];
    }

    public function testClearRevoked(): void
    {
        $inMemoryAuthCodeManager = new InMemoryAuthCodeManager($this->clock);

        $testData = $this->buildClearRevokedTestData();

        foreach ($testData['input'] as $token) {
            $inMemoryAuthCodeManager->save($token);
        }

        $this->assertSame(2, $inMemoryAuthCodeManager->clearRevoked());
        $this->assertManagerContainsExpectedData($testData['output'], $inMemoryAuthCodeManager);
    }

    private function buildClearRevokedTestData(): array
    {
        $validAuthCodes = [
            '1111' => $this->buildAuthCode('1111', '+1 day'),
            '2222' => $this->buildAuthCode('2222', '+1 hour'),
            '3333' => $this->buildAuthCode('3333', '+1 second'),
        ];

        $revokedAuthCodes = [
            '5555' => $this->buildAuthCode('5555', '-1 day', true),
            '6666' => $this->buildAuthCode('6666', '-1 hour', true),
        ];

        return [
            'input' => $validAuthCodes + $revokedAuthCodes,
            'output' => $validAuthCodes,
        ];
    }

    private function buildAuthCode(string $identifier, string $modify, bool $revoked = false): AuthorizationCode
    {
        $expiry = $this->clock->now()->modify($modify);

        $authorizationCode = new AuthorizationCode(
            $identifier,
            $expiry,
            new Client('client', 'secret'),
            null,
            []
        );

        if ($revoked) {
            $authorizationCode->revoke();
        }

        return $authorizationCode;
    }

    private function assertManagerContainsExpectedData(array $output, InMemoryAuthCodeManager $inMemoryAuthCodeManager): void
    {
        $reflectionProperty = new ReflectionProperty(InMemoryAuthCodeManager::class, 'authorizationCodes');
        $reflectionProperty->setAccessible(true);

        $this->assertSame($output, $reflectionProperty->getValue($inMemoryAuthCodeManager));
    }
}
