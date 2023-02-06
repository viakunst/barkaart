<?php

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Doctrine\DBAL\Result;
use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Kernel as BaseKernel;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Routing\RouterInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\closure;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

require dirname(__DIR__).'/vendor/autoload.php';

enum Role
{
    case User;
    case Admin;
}

class Kernel extends BaseKernel
{
    use MicroKernelTrait;

    public function registerBundles(): array
    {
        return [
            new Doctrine\Bundle\DoctrineBundle\DoctrineBundle(),
            new Symfony\Bundle\FrameworkBundle\FrameworkBundle(),
        ];
    }
    
    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import(__FILE__, 'annotation');
    }

    protected function configureContainer(ContainerConfigurator $containerConfigurator): void
    {
        $config = require_once dirname(__DIR__).'/config.php';
        
        $containerConfigurator->extension('doctrine', [
            'dbal' => [
                'dbname' => $config['db_name'],
                'host' => $config['db_host'],
                'user' => $config['db_user'],
                'password' => $config['db_pass'],
            ],
        ]);

        $containerConfigurator->services()
            ->set(OpenIDConnectClient::class)
            ->class(OpenIDConnectClient::class)
            ->args([
                $config['oidc_provider'],
                $config['oidc_id'] ?? null,
                $config['oidc_secret'] ?? null,
                $config['oidc_issuer'] ?? null
            ])
        ;
        
        $containerConfigurator->services()
            ->set(SecurityProvider::class)
            ->class(SecurityProvider::class)
            ->public()
            ->args([
                service(OpenIDConnectClient::class),
                closure([$this, 'isAdmin']),
                $config['secret']
            ])
        ;
        
        $containerConfigurator->services()
            ->set(ExceptionListener::class)
            ->class(ExceptionListener::class)
            ->tag('kernel.event_listener')
        ;
        
        $containerConfigurator->services()
            ->set(ExceptionListener::class)
            ->class(ExceptionListener::class)
            ->tag('kernel.event_listener')
        ;
    }

    public function isAdmin($user): bool
    {
        $found = $this->query("SELECT COUNT(*) FROM `authorized_admins` WHERE `email` = :email", [
            'email' => $user->email,
        ])->fetchOne();
        return $found > 0;
    }

    // initial page, with login functionality
    #[Route('/', name: 'index')]
    public function indexAction(SecurityProvider $security): Response
    {
        $this->install();
        if (!$this->isAuthorized(Role::User)) {
            $security->authorize();
        }

        return self::render(function () {
            if ($this->isAuthorized(Role::Admin)) {
                ?>
                <a href="/generate/10">Genereer 10 euro barkaarten</a>
                <a href="/generate/5">Genereer 5 euro barkaarten</a>
                <?php
            }
            ?>
            <a href="/code/">Bekijk barkaart details</a>
            <a href="/logout">Uitloggen</a>
            <?php
        });
    }
    
    // logout the current user
    #[Route('/logout', name: 'logout')]
    public function logoutAction(SecurityProvider $security): Response
    {
        $security->logout();
        return self::render('Succesvol uitgelogd!');
    }

    // validate a code and signature
    #[Route('/code/{code}', name: 'code')]
    public function codeAction(string $code, Request $request, SecurityProvider $security): Response
    {
        // if a signature was provided, boolean value whether it's valid, null otherwise 
        $query = $request->query;
        list($signatureVersion, $validSignature) = match (true) {
            null === $sig   = $query->get('sig')   => [null, null], // no signature provided
            null !== $value = $query->get('value') => [1, $security->verify("$code:$value.", $sig)],
            default                                => [0, $security->verify($code, $sig)], // only A00-A99
        };

        // register new barkaart if not present and properly authenticated
        $registered = $this->retrieveRegistration($code);
        if ($registered === null && $validSignature && $this->isAuthorized(Role::User)) {
            $registered = [
                'code' => $code,
                'value' => $value ?? 50, // default value for A00-A99
            ];
            $this->query("INSERT INTO `registered_barkaart` (`code`, `value`) VALUES (:code, :value)", $registered);
        }

        // always provide code for rendering purposes
        if ($registered === null) {
            $registered = ['code' => $code];
        }

        return self::render(function (
            string $host,
            ?array $barkaart,
            ?string $userIdentifier,
            ?int $signatureVersion,
            ?bool $validSignature,
        ) {
            $code = $barkaart['code'];
            $barkaart = isset($barkaart['value']) ? $barkaart : null;
            switch (true) {
                case $marked = $barkaart['marked_at']: echo "Barkaart '$code' is verlopen!!!<br>Verlopen op $marked."; break;
                case $at = $barkaart['registered_at']: echo "Barkaart '$code' geregistreerd op $at."; break;
                case $barkaart:                        echo "Barkaart '$code' zojuist geregisteerd!"; break;
                default:                               echo "Barkaart '$code' nog niet bekend."; break;
            }
            
            if ($userIdentifier && $userIdentifier === $barkaart['marked_by']) { ?>
                <a href="<?php echo $this->routeTo('revalidate', ['code' => $code]) ?>">Klik hier</a> om ongedaan te maken.
            <?php } ?>
            <br><br>
            <?php
            if ($barkaart && !$barkaart['marked_at']) {
                if ($userIdentifier !== null) { ?>
                    <a href="<?php echo $this->routeTo('invalidate', ['code' => $code]) ?>">Maak deze barkaart ongeldig</a>
                <?php } else { ?>
                    Barkaarten ongeldig maken kan alleen wanneer ingelogd, <a href='/'>klik hier</a> om in te loggen.
                <?php }
            } ?>
            <br><br>
            <?php
            if (null !== $validSignature) {
                echo $validSignature ? "Geldige QR-code.<br>LET OP: check altijd of dit adres $host is." : "Incorrecte QR-code!!!";
                if ($validSignature && $signatureVersion === 0) {
                    echo 'QR code alleen geldige voor A00-A99';
                }
            } ?>

            <br><br>
            <?php if ($this->isAuthorized(Role::Admin) && $barkaart && !isset($registered['marked_at'])) { ?>
                <a href="<?php echo $this->routeTo('remove', ['code' => $code]) ?>">Verwijder deze barkaart registratie</a>
                <br>
                LET OP: Alleen gebruiken voor foutief geregistreerde barkaarten
            <?php }
        }, [
            'host' => $request->getHost(),
            'barkaart' => $registered,
            'userIdentifier' => $security->getUserIdentifier(),
            'signatureVersion' => $signatureVersion,
            'validSignature' => $validSignature,
        ]);
    }

    // remove a registered code altogether
    #[Route('/remove/{code}', name: 'remove')]
    public function removeAction(string $code): Response
    {
        $this->denyAccessUnlessGranted(Role::Admin, 'Alleen beheerders kunnen kaarten verwijderen');
        $this->denyAccessIfNotFound($this->retrieveRegistration($code), "Barkaart '$code' niet gevonden.");
        
        // execute
        $this->query("DELETE FROM `registered_barkaart` WHERE `code` = :code", ['code' => $code]);

        return self::render("Barkaart $code is verwijderd!");
    }

    // revalidate an earlier invalidated code
    #[Route('/revalidate/{code}', name: 'revalidate')]
    public function revalidateAction(string $code, SecurityProvider $security): Response
    {
        $this->denyAccessUnlessGranted(Role::User, 'Je moet ingelogd zijn om een barkaart geldig te maken');
        $this->denyAccessIfNotFound($details = $this->retrieveRegistration($code), "Barkaart '$code' niet gevonden.");
        
        if ($security->getUserIdentifier() !== $details['marked_by'])
        {
            throw new AccessDeniedHttpException("Alleen de gebruiker die een barkaart ongeldig heeft gemaakt kan deze opnieuw geldig maken");
        }
        
        // execute
        $this->query("UPDATE `registered_barkaart` SET `marked_at` = NULL, `marked_by` = NULL WHERE `code` = :code", ['code' => $code]);

        return self::render("Barkaart $code is opnieuw geldig gemaakt!");
    }

    // invalidate a code
    #[Route('/invalidate/{code}', name: 'invalidate')]
    public function invalidateAction(string $code, SecurityProvider $security): Response
    {
        $this->denyAccessUnlessGranted(Role::User, 'Je moet ingelogd zijn om een barkaart ongeldig te maken');
        $this->denyAccessIfNotFound($this->retrieveRegistration($code), "Barkaart '$code' niet gevonden. Registeer eerst <a href='/code/$code'>hier</a>");
        
        // execute
        $this->query("UPDATE `registered_barkaart` SET `marked_at` = CURRENT_TIMESTAMP, `marked_by` = :author WHERE `code` = :code AND `marked_at` IS NULL", [
            'author' => $security->getUserIdentifier(),
            'code' => $code
        ]);

        return self::render("Barkaart $code is ongeldig gemaakt!<br><a href='/revalidate/$code'>Klik hier</a> om ongedaan te maken");
    }

    // in all other cases, generate new cards
    #[Route('/generate/{size}', name: 'generate')]
    public function generateAction(int $size, SecurityProvider $security): Response
    {
        $this->denyAccessUnlessGranted(Role::Admin);

        // extract prefix
        $prefix = strtoupper($_GET["prefix"]);
        if (!$prefix) {
            return self::render('Please provide a prefix');
        }
        
        return self::render(function (int $size, string $prefix, SecurityProvider $security) {
            foreach (range(0, 99) as $number) {
                $code = $prefix.str_pad($number, 2, '0', STR_PAD_LEFT);
                $value = $size * 10;
                $sig = $security->sign("$code:$value.");
                ?>
                <div class="page">
                    <p class="header">ViaKunst barkaart - <?php echo $code; ?></p>
                    <?php echo $this->generate_table($size, 10); ?>
                    <div class="qr"><?php echo $this->generate_qr($code, $sig, $value); ?></div>
                </div>
                <?php
            }
        }, ['size' => $size, 'prefix' => $prefix, 'security' => $security]);
    }

    private function routeTo(string $name, array $parameters = [], int $referenceType = RouterInterface::ABSOLUTE_URL): string
    {
        return $this->getContainer()->get('router')->generate($name, $parameters, $referenceType);
    }
    
    private function generate_qr($code, $signature, $value): string
    {
        $url = $this->routeTo('code', [
            'code' => $code,
            'value' => $value,
            'sig' => $signature,
        ]);

        $renderer = new ImageRenderer(
            new RendererStyle(150),
            new SvgImageBackEnd()
        );
        
        $writer = new Writer($renderer);

        return $writer->writeString($url);
    }

    private function generate_table($width, $height): string
    {
        $content = '';
        for ($i = 1; $i <= $height * $width; $i++) {
            $content .= '<td>'.$i.'</td>';
            if ($i % $width == 0) $content .= '</tr><tr>';
        }
        return '<table><tr>'.$content.'</tr></table>';
    }

    private function isAuthorized(Role $role = Role::User): bool
    {
        $asAdmin = match ($role) {
            Role::Admin => true,
            default => false,
        };

        return $this->getContainer()->get(SecurityProvider::class)->isAuthorized($asAdmin);
    }

    private function denyAccessUnlessGranted(Role $role = Role::User, string $message = 'Geen toegang.'): void
    {
        if (!$this->isAuthorized($role)) {
            throw new AccessDeniedHttpException($message);
        }
    }
    
    private function denyAccessIfNotFound($attribute, string $message = 'Niet gevonden.'): void
    {
        if (null === $attribute) {
            throw new NotFoundHttpException($message);
        }
    }

    private function query(string $sql, array $params = null): Result
    {
        $connection = $this->getContainer()->get('doctrine')->getConnection();
        return $connection->prepare($sql)->execute($params);
    }

    private function retrieveRegistration($code): ?array
    {
        $query = $this->query("SELECT * FROM `registered_barkaart` WHERE `code` = :code", ['code' => $code]);
        return $query->fetchAssociative() ?: null;
    }

    private function install(): void
    {
        // create necessary tables
        try {
            $result = $this->query("DESCRIBE `registered_barkaart`");
            $result->fetchAllAssociative();
        } catch (\Exception $_) {
            $this->query("CREATE TABLE `registered_barkaart` (
                `code` VARCHAR(255) NOT NULL PRIMARY KEY,
                `value` SMALLINT NOT NULL,
                `registered_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                `marked_by` VARCHAR(1024) DEFAULT NULL,
                `marked_at` TIMESTAMP NULL DEFAULT NULL
            )");
        }

        try {
            $result = $this->query("DESCRIBE `authorized_admins`");
            $result->fetchAllAssociative();
        } catch (\Exception $_) {
            $this->query("CREATE TABLE `authorized_admins` (
                `email` VARCHAR(1024) NOT NULL PRIMARY KEY
            )");
        }
    }

    public static function render(string|callable $body, array $params = [], int $status = 200, array $headers = []): Response
    {
        $image = '';
        if (filter_var($url = $_GET['image_url'], FILTER_VALIDATE_URL)) {
            $image = $url;
        }

        ob_start();
        ?>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                @import url(https://fonts.googleapis.com/css2?family=Poppins:wght@400);
                body
                {
                    font-family: "Poppins",Helvetica,sans-serif;
                    font-weight: 400;
                    -webkit-font-smoothing: antialiased;
                }
                div.page
                {
                    page-break-after: auto;
                    page-break-inside: avoid;
                    float: left;
                    margin: 5px;
                    padding: 15px;
                    background-repeat: no-repeat;
                    background-position: center;
                    background-size: cover;
                    background-image: linear-gradient(rgba(255,255,255,0.5), rgba(255,255,255,0.5)), url('<?php echo $image ?>');
                }
                .header
                {
                    width: 218px;
                    text-align: center;
                }
                div.qr
                {
                    display: block;
                    text-align: center;
                }
                table
                {
                    margin-left: auto;
                    margin-right: auto;
                }
                table, th, td {
                    border: 1px solid black;
                    border-collapse: collapse;
                    margin-bottom: 5px;
                }
                td {
                    width: 30px;
                    height: 30px;
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <?php
            // get page contents using output buffering
            if (!is_string($body)) {
                call_user_func_array($body, $params);
            } else {
                echo $body;
            }
            ?>
        </body>
        <?php

        $page = ob_get_contents();
        ob_end_clean();

        // return a response
        return new Response($page, $status, $headers);
    }
}

class SecurityProvider
{
    /** @var ?stdClass $user */
    private $user = null;

    public function __construct(
        private OpenIDConnectClient $oidc,
        private $adminProvider,
        private $secretKey,
    ) {
        session_start();
        $this->reloadUser();
    }

    public function sign(string $content)
    {
        return password_hash($content.$this->secretKey, PASSWORD_DEFAULT);
    }

    public function verify(string $content, string $signature): bool
    {
        return password_verify($content.$this->secretKey, $signature);
    }

    public function getUserIdentifier(): ?string
    {
        return null !== $this->user ? $this->user->sub : null;
    }

    public function isAuthorized(bool $adminPrivilegesRequired = false): bool
    {
        if ($this->user === null)
            return false;

        return $adminPrivilegesRequired ? call_user_func($this->adminProvider, $this->user) : true;
    }

    public function authorize(): void
    {
        try {
            if (!$this->oidc->authenticate()) {
                throw new OpenIDConnectClientException('Authentication failed');
            }
            $this->user = $this->oidc->requestUserInfo();
            $_SESSION['access_token'] = $this->oidc->getAccessToken();
            $this->storeRefresh();
        } catch (OpenIDConnectClientException $_) {
            // connection has failed, exit
            unset($_SESSION['access_token']);
            $this->destroyRefresh();
        }
    }

    public function logout(): void
    {
        unset($_SESSION['access_token']);
        $this->destroyRefresh();
    }

    private function reloadUser()
    {
        // retrieve user through access token from session
        if (isset($_SESSION['access_token'])) {
            $this->oidc->setAccessToken($_SESSION['access_token']);
            try {
                $this->user = $this->oidc->requestUserInfo();
            } catch (OpenIDConnectClientException $e) {
                // access token is expired, remove it
                $this->oidc->setAccessToken(null);
                unset($_SESSION['access_token']);
            }
        }

        // refresh access token if access token was expired
        if (null === $this->user && isset($_COOKIE['refresh_token'])) {
            $this->oidc->refreshToken($_COOKIE['refresh_token']);
            $_SESSION['access_token'] = $this->oidc->getAccessToken();
            $this->storeRefresh();
            try {
                $this->user = $this->oidc->requestUserInfo();
            } catch (OpenIDConnectClientException $e) {
                // connection has failed
                unset($_SESSION['access_token']);
                $this->destroyRefresh();
            }
        }
    }
    
    private function storeRefresh()
    {
        $refresh = $this->oidc->getRefreshToken();
        if (!$refresh) {
            $this->destroyRefresh();
            return;
        }

        $expire = time()+60*60*24*30; // 30 days from now
        setcookie('refresh_token', $refresh, $expire, '/', "", true, true);
    }

    private function destroyRefresh() {
        if (isset($_COOKIE['refresh_token'])) {
            unset($_COOKIE['refresh_token']); 
            setcookie('refresh_token', null, time() - 3600, '/', "", true, true); // one hour ago
        }
    }
}

class ExceptionListener
{
    public function __invoke(ExceptionEvent $event): void
    {
        // You get the exception object from the received event
        $exception = $event->getThrowable();

        // HttpExceptionInterface is a special type of exception that
        // holds status code and header details
        if ($exception instanceof HttpExceptionInterface) {
            $response = Kernel::render($exception->getMessage());
            $response->setStatusCode($exception->getStatusCode());
            $response->headers->replace($exception->getHeaders());
            $event->setResponse($response);
        }
    }
}

$kernel = new Kernel('prod', false);
$request = Request::createFromGlobals();
$response = $kernel->handle($request);
$response->send();
$kernel->terminate($request, $response);