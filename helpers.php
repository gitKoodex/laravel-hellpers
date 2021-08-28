<?php

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Broadcasting\Factory as BroadcastFactory;
use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Contracts\Cookie\Factory as CookieFactory;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Foundation\Bus\PendingClosureDispatch;
use Illuminate\Foundation\Bus\PendingDispatch;
use Illuminate\Foundation\Mix;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Queue\CallQueuedClosure;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\HtmlString;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Foundation\Jdate;
use Illuminate\Foundation\GoogleTranslate;

if (! function_exists('abort')) {
    /**
     * Throw an HttpException with the given data.
     *
     * @param  \Symfony\Component\HttpFoundation\Response|\Illuminate\Contracts\Support\Responsable|int  $code
     * @param  string  $message
     * @param  array  $headers
     * @return void
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     * @throws \Symfony\Component\HttpKernel\Exception\NotFoundHttpException
     */
    function abort($code, $message = '', array $headers = [])
    {
        if ($code instanceof Response) {
            throw new HttpResponseException($code);
        } elseif ($code instanceof Responsable) {
            throw new HttpResponseException($code->toResponse(request()));
        }

        app()->abort($code, $message, $headers);
    }
}

if (! function_exists('abort_if')) {
    /**
     * Throw an HttpException with the given data if the given condition is true.
     *
     * @param  bool  $boolean
     * @param  \Symfony\Component\HttpFoundation\Response|\Illuminate\Contracts\Support\Responsable|int  $code
     * @param  string  $message
     * @param  array  $headers
     * @return void
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     * @throws \Symfony\Component\HttpKernel\Exception\NotFoundHttpException
     */
    function abort_if($boolean, $code, $message = '', array $headers = [])
    {
        if ($boolean) {
            abort($code, $message, $headers);
        }
    }
}

if (! function_exists('abort_unless')) {
    /**
     * Throw an HttpException with the given data unless the given condition is true.
     *
     * @param  bool  $boolean
     * @param  \Symfony\Component\HttpFoundation\Response|\Illuminate\Contracts\Support\Responsable|int  $code
     * @param  string  $message
     * @param  array  $headers
     * @return void
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     * @throws \Symfony\Component\HttpKernel\Exception\NotFoundHttpException
     */
    function abort_unless($boolean, $code, $message = '', array $headers = [])
    {
        if (! $boolean) {
            abort($code, $message, $headers);
        }
    }
}

if (! function_exists('action')) {
    /**
     * Generate the URL to a controller action.
     *
     * @param  string|array  $name
     * @param  mixed  $parameters
     * @param  bool  $absolute
     * @return string
     */
    function action($name, $parameters = [], $absolute = true)
    {
        return app('url')->action($name, $parameters, $absolute);
    }
}

if (! function_exists('app')) {
    /**
     * Get the available container instance.
     *
     * @param  string|null  $abstract
     * @param  array  $parameters
     * @return mixed|\Illuminate\Contracts\Foundation\Application
     */
    function app($abstract = null, array $parameters = [])
    {
        if (is_null($abstract)) {
            return Container::getInstance();
        }

        return Container::getInstance()->make($abstract, $parameters);
    }
}

if (! function_exists('app_path')) {
    /**
     * Get the path to the application folder.
     *
     * @param  string  $path
     * @return string
     */
    function app_path($path = '')
    {
        return app()->path($path);
    }
}

if (! function_exists('asset')) {
    /**
     * Generate an asset path for the application.
     *
     * @param  string  $path
     * @param  bool|null  $secure
     * @return string
     */
    function asset($path, $secure = null)
    {
        return app('url')->asset($path, $secure);
    }
}

if (! function_exists('auth')) {
    /**
     * Get the available auth instance.
     *
     * @param  string|null  $guard
     * @return \Illuminate\Contracts\Auth\Factory|\Illuminate\Contracts\Auth\Guard|\Illuminate\Contracts\Auth\StatefulGuard
     */
    function auth($guard = null)
    {
        if (is_null($guard)) {
            return app(AuthFactory::class);
        }

        return app(AuthFactory::class)->guard($guard);
    }
}

if (! function_exists('back')) {
    /**
     * Create a new redirect response to the previous location.
     *
     * @param  int  $status
     * @param  array  $headers
     * @param  mixed  $fallback
     * @return \Illuminate\Http\RedirectResponse
     */
    function back($status = 302, $headers = [], $fallback = false)
    {
        return app('redirect')->back($status, $headers, $fallback);
    }
}

if (! function_exists('base_path')) {
    /**
     * Get the path to the base of the install.
     *
     * @param  string  $path
     * @return string
     */
    function base_path($path = '')
    {
        return app()->basePath($path);
    }
}

if (! function_exists('bcrypt')) {
    /**
     * Hash the given value against the bcrypt algorithm.
     *
     * @param  string  $value
     * @param  array  $options
     * @return string
     */
    function bcrypt($value, $options = [])
    {
        return app('hash')->driver('bcrypt')->make($value, $options);
    }
}

if (! function_exists('broadcast')) {
    /**
     * Begin broadcasting an event.
     *
     * @param  mixed|null  $event
     * @return \Illuminate\Broadcasting\PendingBroadcast
     */
    function broadcast($event = null)
    {
        return app(BroadcastFactory::class)->event($event);
    }
}

if (! function_exists('cache')) {
    /**
     * Get / set the specified cache value.
     *
     * If an array is passed, we'll assume you want to put to the cache.
     *
     * @param  dynamic  key|key,default|data,expiration|null
     * @return mixed|\Illuminate\Cache\CacheManager
     *
     * @throws \Exception
     */
    function cache()
    {
        $arguments = func_get_args();

        if (empty($arguments)) {
            return app('cache');
        }

        if (is_string($arguments[0])) {
            return app('cache')->get(...$arguments);
        }

        if (! is_array($arguments[0])) {
            throw new Exception(
                'When setting a value in the cache, you must pass an array of key / value pairs.'
            );
        }

        return app('cache')->put(key($arguments[0]), reset($arguments[0]), $arguments[1] ?? null);
    }
}

if (! function_exists('config')) {
    /**
     * Get / set the specified configuration value.
     *
     * If an array is passed as the key, we will assume you want to set an array of values.
     *
     * @param  array|string|null  $key
     * @param  mixed  $default
     * @return mixed|\Illuminate\Config\Repository
     */
    function config($key = null, $default = null)
    {
        if (is_null($key)) {
            return app('config');
        }

        if (is_array($key)) {
            return app('config')->set($key);
        }

        return app('config')->get($key, $default);
    }
}

if (! function_exists('config_path')) {
    /**
     * Get the configuration path.
     *
     * @param  string  $path
     * @return string
     */
    function config_path($path = '')
    {
        return app()->configPath($path);
    }
}

if (! function_exists('cookie')) {
    /**
     * Create a new cookie instance.
     *
     * @param  string|null  $name
     * @param  string|null  $value
     * @param  int  $minutes
     * @param  string|null  $path
     * @param  string|null  $domain
     * @param  bool|null  $secure
     * @param  bool  $httpOnly
     * @param  bool  $raw
     * @param  string|null  $sameSite
     * @return \Illuminate\Cookie\CookieJar|\Symfony\Component\HttpFoundation\Cookie
     */
    function cookie($name = null, $value = null, $minutes = 0, $path = null, $domain = null, $secure = null, $httpOnly = true, $raw = false, $sameSite = null)
    {
        $cookie = app(CookieFactory::class);

        if (is_null($name)) {
            return $cookie;
        }

        return $cookie->make($name, $value, $minutes, $path, $domain, $secure, $httpOnly, $raw, $sameSite);
    }
}

if (! function_exists('csrf_field')) {
    /**
     * Generate a CSRF token form field.
     *
     * @return \Illuminate\Support\HtmlString
     */
    function csrf_field()
    {
        return new HtmlString('<input type="hidden" name="_token" value="'.csrf_token().'">');
    }
}

if (! function_exists('csrf_token')) {
    /**
     * Get the CSRF token value.
     *
     * @return string
     *
     * @throws \RuntimeException
     */
    function csrf_token()
    {
        $session = app('session');

        if (isset($session)) {
            return $session->token();
        }

        throw new RuntimeException('Application session store not set.');
    }
}

if (! function_exists('database_path')) {
    /**
     * Get the database path.
     *
     * @param  string  $path
     * @return string
     */
    function database_path($path = '')
    {
        return app()->databasePath($path);
    }
}

if (! function_exists('decrypt')) {
    /**
     * Decrypt the given value.
     *
     * @param  string  $value
     * @param  bool  $unserialize
     * @return mixed
     */
    function decrypt($value, $unserialize = true)
    {
        return app('encrypter')->decrypt($value, $unserialize);
    }
}

if (! function_exists('dispatch')) {
    /**
     * Dispatch a job to its appropriate handler.
     *
     * @param  mixed  $job
     * @return \Illuminate\Foundation\Bus\PendingDispatch
     */
    function dispatch($job)
    {
        return $job instanceof Closure
                ? new PendingClosureDispatch(CallQueuedClosure::create($job))
                : new PendingDispatch($job);
    }
}

if (! function_exists('dispatch_now')) {
    /**
     * Dispatch a command to its appropriate handler in the current process.
     *
     * @param  mixed  $job
     * @param  mixed  $handler
     * @return mixed
     */
    function dispatch_now($job, $handler = null)
    {
        return app(Dispatcher::class)->dispatchNow($job, $handler);
    }
}

if (! function_exists('encrypt')) {
    /**
     * Encrypt the given value.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return string
     */
    function encrypt($value, $serialize = true)
    {
        return app('encrypter')->encrypt($value, $serialize);
    }
}

if (! function_exists('event')) {
    /**
     * Dispatch an event and call the listeners.
     *
     * @param  string|object  $event
     * @param  mixed  $payload
     * @param  bool  $halt
     * @return array|null
     */
    function event(...$args)
    {
        return app('events')->dispatch(...$args);
    }
}

if (! function_exists('info')) {
    /**
     * Write some information to the log.
     *
     * @param  string  $message
     * @param  array  $context
     * @return void
     */
    function info($message, $context = [])
    {
        app('log')->info($message, $context);
    }
}

if (! function_exists('logger')) {
    /**
     * Log a debug message to the logs.
     *
     * @param  string|null  $message
     * @param  array  $context
     * @return \Illuminate\Log\LogManager|null
     */
    function logger($message = null, array $context = [])
    {
        if (is_null($message)) {
            return app('log');
        }

        return app('log')->debug($message, $context);
    }
}

if (! function_exists('logs')) {
    /**
     * Get a log driver instance.
     *
     * @param  string|null  $driver
     * @return \Illuminate\Log\LogManager|\Psr\Log\LoggerInterface
     */
    function logs($driver = null)
    {
        return $driver ? app('log')->driver($driver) : app('log');
    }
}

if (! function_exists('method_field')) {
    /**
     * Generate a form field to spoof the HTTP verb used by forms.
     *
     * @param  string  $method
     * @return \Illuminate\Support\HtmlString
     */
    function method_field($method)
    {
        return new HtmlString('<input type="hidden" name="_method" value="'.$method.'">');
    }
}

if (! function_exists('mix')) {
    /**
     * Get the path to a versioned Mix file.
     *
     * @param  string  $path
     * @param  string  $manifestDirectory
     * @return \Illuminate\Support\HtmlString|string
     *
     * @throws \Exception
     */
    function mix($path, $manifestDirectory = '')
    {
        return app(Mix::class)(...func_get_args());
    }
}

if (! function_exists('now')) {
    /**
     * Create a new Carbon instance for the current time.
     *
     * @param  \DateTimeZone|string|null  $tz
     * @return \Illuminate\Support\Carbon
     */
    function now($tz = null)
    {
        return Date::now($tz);
    }
}

if (! function_exists('old')) {
    /**
     * Retrieve an old input item.
     *
     * @param  string|null  $key
     * @param  mixed  $default
     * @return mixed
     */
    function old($key = null, $default = null)
    {
        return app('request')->old($key, $default);
    }
}

if (! function_exists('policy')) {
    /**
     * Get a policy instance for a given class.
     *
     * @param  object|string  $class
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    function policy($class)
    {
        return app(Gate::class)->getPolicyFor($class);
    }
}

if (! function_exists('public_path')) {
    /**
     * Get the path to the public folder.
     *
     * @param  string  $path
     * @return string
     */
    function public_path($path = '')
    {
        return app()->make('path.public').($path ? DIRECTORY_SEPARATOR.ltrim($path, DIRECTORY_SEPARATOR) : $path);
    }
}

if (! function_exists('redirect')) {
    /**
     * Get an instance of the redirector.
     *
     * @param  string|null  $to
     * @param  int  $status
     * @param  array  $headers
     * @param  bool|null  $secure
     * @return \Illuminate\Routing\Redirector|\Illuminate\Http\RedirectResponse
     */
    function redirect($to = null, $status = 302, $headers = [], $secure = null)
    {
        if (is_null($to)) {
            return app('redirect');
        }

        return app('redirect')->to($to, $status, $headers, $secure);
    }
}

if (! function_exists('report')) {
    /**
     * Report an exception.
     *
     * @param  \Throwable  $exception
     * @return void
     */
    function report(Throwable $exception)
    {
        app(ExceptionHandler::class)->report($exception);
    }
}

if (! function_exists('request')) {
    /**
     * Get an instance of the current request or an input item from the request.
     *
     * @param  array|string|null  $key
     * @param  mixed  $default
     * @return \Illuminate\Http\Request|string|array
     */
    function request($key = null, $default = null)
    {
        if (is_null($key)) {
            return app('request');
        }

        if (is_array($key)) {
            return app('request')->only($key);
        }

        $value = app('request')->__get($key);

        return is_null($value) ? value($default) : $value;
    }
}

if (! function_exists('rescue')) {
    /**
     * Catch a potential exception and return a default value.
     *
     * @param  callable  $callback
     * @param  mixed  $rescue
     * @param  bool  $report
     * @return mixed
     */
    function rescue(callable $callback, $rescue = null, $report = true)
    {
        try {
            return $callback();
        } catch (Throwable $e) {
            if ($report) {
                report($e);
            }

            return $rescue instanceof Closure ? $rescue($e) : $rescue;
        }
    }
}

if (! function_exists('resolve')) {
    /**
     * Resolve a service from the container.
     *
     * @param  string  $name
     * @param  array  $parameters
     * @return mixed
     */
    function resolve($name, array $parameters = [])
    {
        return app($name, $parameters);
    }
}

if (! function_exists('resource_path')) {
    /**
     * Get the path to the resources folder.
     *
     * @param  string  $path
     * @return string
     */
    function resource_path($path = '')
    {
        return app()->resourcePath($path);
    }
}

if (! function_exists('response')) {
    /**
     * Return a new response from the application.
     *
     * @param  \Illuminate\Contracts\View\View|string|array|null  $content
     * @param  int  $status
     * @param  array  $headers
     * @return \Illuminate\Http\Response|\Illuminate\Contracts\Routing\ResponseFactory
     */
    function response($content = '', $status = 200, array $headers = [])
    {
        $factory = app(ResponseFactory::class);

        if (func_num_args() === 0) {
            return $factory;
        }

        return $factory->make($content, $status, $headers);
    }
}

if (! function_exists('route')) {
    /**
     * Generate the URL to a named route.
     *
     * @param  array|string  $name
     * @param  mixed  $parameters
     * @param  bool  $absolute
     * @return string
     */
    function route($name, $parameters = [], $absolute = true)
    {
        return app('url')->route($name, $parameters, $absolute);
    }
}

if (! function_exists('secure_asset')) {
    /**
     * Generate an asset path for the application.
     *
     * @param  string  $path
     * @return string
     */
    function secure_asset($path)
    {
        return asset($path, true);
    }
}

if (! function_exists('secure_url')) {
    /**
     * Generate a HTTPS url for the application.
     *
     * @param  string  $path
     * @param  mixed  $parameters
     * @return string
     */
    function secure_url($path, $parameters = [])
    {
        return url($path, $parameters, true);
    }
}

if (! function_exists('session')) {
    /**
     * Get / set the specified session value.
     *
     * If an array is passed as the key, we will assume you want to set an array of values.
     *
     * @param  array|string|null  $key
     * @param  mixed  $default
     * @return mixed|\Illuminate\Session\Store|\Illuminate\Session\SessionManager
     */
    function session($key = null, $default = null)
    {
        if (is_null($key)) {
            return app('session');
        }

        if (is_array($key)) {
            return app('session')->put($key);
        }

        return app('session')->get($key, $default);
    }
}

if (! function_exists('storage_path')) {
    /**
     * Get the path to the storage folder.
     *
     * @param  string  $path
     * @return string
     */
    function storage_path($path = '')
    {
        return app('path.storage').($path ? DIRECTORY_SEPARATOR.$path : $path);
    }
}

if (! function_exists('today')) {
    /**
     * Create a new Carbon instance for the current date.
     *
     * @param  \DateTimeZone|string|null  $tz
     * @return \Illuminate\Support\Carbon
     */
    function today($tz = null)
    {
        return Date::today($tz);
    }
}

if (! function_exists('trans')) {
    /**
     * Translate the given message.
     *
     * @param  string|null  $key
     * @param  array  $replace
     * @param  string|null  $locale
     * @return \Illuminate\Contracts\Translation\Translator|string|array|null
     */
    function trans($key = null, $replace = [], $locale = null)
    {
        if (is_null($key)) {
            return app('translator');
        }

        return app('translator')->get($key, $replace, $locale);
    }
}

if (! function_exists('trans_choice')) {
    /**
     * Translates the given message based on a count.
     *
     * @param  string  $key
     * @param  \Countable|int|array  $number
     * @param  array  $replace
     * @param  string|null  $locale
     * @return string
     */
    function trans_choice($key, $number, array $replace = [], $locale = null)
    {
        return app('translator')->choice($key, $number, $replace, $locale);
    }
}

if (! function_exists('__')) {
    /**
     * Translate the given message.
     *
     * @param  string|null  $key
     * @param  array  $replace
     * @param  string|null  $locale
     * @return string|array|null
     */
    function __($key = null, $replace = [], $locale = null)
    {
        if (is_null($key)) {
            return $key;
        }

        return trans($key, $replace, $locale);
    }
}

if (! function_exists('url')) {
    /**
     * Generate a url for the application.
     *
     * @param  string|null  $path
     * @param  mixed  $parameters
     * @param  bool|null  $secure
     * @return \Illuminate\Contracts\Routing\UrlGenerator|string
     */
    function url($path = null, $parameters = [], $secure = null)
    {
        if (is_null($path)) {
            return app(UrlGenerator::class);
        }

        return app(UrlGenerator::class)->to($path, $parameters, $secure);
    }

}

if (! function_exists('validator')) {
    /**
     * Create a new Validator instance.
     *
     * @param  array  $data
     * @param  array  $rules
     * @param  array  $messages
     * @param  array  $customAttributes
     * @return \Illuminate\Contracts\Validation\Validator|\Illuminate\Contracts\Validation\Factory
     */
    function validator(array $data = [], array $rules = [], array $messages = [], array $customAttributes = [])
    {
        $factory = app(ValidationFactory::class);

        if (func_num_args() === 0) {
            return $factory;
        }

        return $factory->make($data, $rules, $messages, $customAttributes);
    }
}

if (! function_exists('view')) {
    /**
     * Get the evaluated view contents for the given view.
     *
     * @param  string|null  $view
     * @param  \Illuminate\Contracts\Support\Arrayable|array  $data
     * @param  array  $mergeData
     * @return \Illuminate\Contracts\View\View|\Illuminate\Contracts\View\Factory
     */
    function view($view = null, $data = [], $mergeData = [])
    {
        $factory = app(ViewFactory::class);

        if (func_num_args() === 0) {
            return $factory;
        }

        return $factory->make($view, $data, $mergeData);
    }
}

//my functions
/*
|--------------------------------------------------------------------------
| showSuccessMsg
|--------------------------------------------------------------------------
|
| you send two string with arogumants.
| we return structure of bootstrap success message.
| example: <? echo showSuccessMsg("create pruduct","on store")?>
|
*/
if (! function_exists('showSuccessMsg')) {
    function showSuccessMsg(string $name, string $type)
    {
        return '<div class="alert alert-success alert-dismissible mrt20">
					<button type="button" class="close" data-dismiss="alert" aria-hidden="true">×</button>
					<h5><i class="icon fa fa-check"></i> ' . $type . ' ' . $name . ' با موفقیت انجام شد!</h5>
				  </div>';
    }
}
/*
|--------------------------------------------------------------------------
| showErrorMsg
|--------------------------------------------------------------------------
|
| send two string to this function.
| we return structure of bootstrap Error message.
| example: <? echo showErrorMsg("create pruduct","on store")?>
|
*/
if (! function_exists('showErrorMsg')){
    function showErrorMsg(string $name,string $type) {
        global $conn;
        return '<div class="alert alert-danger  alert-dismissible mrt20">
					<button type="button" class="close" data-dismiss="alert" aria-hidden="true">×</button>
					<h5><i class="icon fa fa-ban"></i> ' . $type . ' ' . $name . ' با خطا مواجه شد!</h5>
					<p>لطفا مجددا تلاش کنید. در صورت تکرار خطا با مدیر سیستمتماس بگیرید</p>
					<br>
				  </div>';
    }
}
/*
|--------------------------------------------------------------------------
| is_json
|--------------------------------------------------------------------------
|
| you send two string with arogumants.
| we return structure of bootstrap success message.
| example: <? echo showSuccessMsg("create pruduct","on store")?>
|
*/
if (! function_exists('is_json')) {
    function is_json($string, $return_data = false, $assoc = false)
    {
        if (!is_string($string)) return false;
        $data = json_decode($string, $assoc);
        return (json_last_error() == JSON_ERROR_NONE) ? is_array($data) || is_object($data) ? ($return_data ? $data : TRUE) : FALSE : FALSE;
    }
}

/*
|--------------------------------------------------------------------------
| showResult
|--------------------------------------------------------------------------
|
| when you call controller by ajax you cat use this
| for check controller done job or fail.
| you can add your condition
|
*/
if (! function_exists('showResult')) {
    function showResult($method, $name, $type)
    {
        if ($method) {
            return showSuccessMsg($name, $type);
        } else {
            return showErrorMsg($name, $type);
        }
    }
}
/*
|--------------------------------------------------------------------------
| strToArray
|--------------------------------------------------------------------------
|
| you send string and seprator
| function return array by explode
|
|
*/
if (! function_exists('strToArray')) {
    function strToArray(string $string,string $sepprator)
    {
        return explode($sepprator, $string);
    }
}

/*
|--------------------------------------------------------------------------
| arrayTostring
|--------------------------------------------------------------------------
|
| you send array and seprator text
| function return string and use seprator beetween each character.
| function use emplode.
|
*/
if (! function_exists('arrayToStr')) {
    function arrayToStr(array $yourArray,string $sepprator)
    {
        return implode($sepprator, $yourArray);
    }
}
/*
|--------------------------------------------------------------------------
| MobileFormat
|--------------------------------------------------------------------------
|
| you send simple mobile number as text
| function return the mobile number with format
| when you show mobile from database to users
| you can use this to make it beautiful.
|
*/
if (! function_exists('MobileFormat')) {
    function MobileFormat($mobile) {

        $mobile = substr_replace(substr_replace(substr_replace(substr_replace($mobile, " ", 9, 0), " ", 7, 0), ") ", 4, 0), "(", 0, 0);
        return $mobile;
    }
}

/*
|--------------------------------------------------------------------------
| TelFormat
|--------------------------------------------------------------------------
|
| you send simple Telphone number as text
| function return the Telphone number with format
| when you show Telphone from database to users
| you can use this to make it beautiful.
|
*/
if (! function_exists('TelFormat')) {
    function TelFormat($tel)
    {
        $tel = substr_replace(substr_replace(substr_replace(substr_replace(substr_replace($tel, " ", 9, 0), " ", 7, 0), " ", 5, 0), ") ", 3, 0), "(", 0, 0);
        return $tel;
    }
}

/*
|--------------------------------------------------------------------------
| CorrectMobile
|--------------------------------------------------------------------------
|
| you send mobile number as text with mobile format(MobileFormat())
| function return correct mobile number as text
|
*/

if (! function_exists('CorrectMobile')) {
    function CorrectMobile($mobile)
    {
        $mobile = preg_replace('/[^0-9]/', '', $mobile);
        return $mobile;
    }
}
/*
|--------------------------------------------------------------------------
| cleanMe
|--------------------------------------------------------------------------
|
| creen text and from html code and mak it ready for save to database
|
|
*/
if (! function_exists('cleanMe')) {
    function cleanMe(string $string)
    {
        if (is_array($string)) {
            $arr = array();
            foreach ($string as $key => $str) {
                $arr[$key] = cleanme($str);
            }
            return $arr;
        } else {
            return htmlspecialchars($string);
        }
    }
}
/*
|--------------------------------------------------------------------------
| passwordGenerator
|--------------------------------------------------------------------------
|
| generate strong password
|
|
*/

if (! function_exists('passwordGenerator')) {
    function passwordGenerator()
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$^%&*';
        $charactersLength = strlen($characters);
        $randomString = '';
        while (!preg_match('/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$^%&*-]).{12,}$/', $randomString)) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }
}
/*
|--------------------------------------------------------------------------
| is_odd
|--------------------------------------------------------------------------
|
| return true if number is odd(فرد)
|
|
*/
if (! function_exists('is_odd')) {
    function is_odd($number)
    {
        if (!is_numeric($number)) {
            throw new Error('Number input is nut numeric');
        } else {
            if ($number % 2 == 0) {
                return true;
            } else {
                return false;
            }
        }
    }
}
/*
|--------------------------------------------------------------------------
| is_even
|--------------------------------------------------------------------------
|
| return true if number is even(زوج)
|
|
*/
if (! function_exists('is_even')) {
    function is_even($number) {
        if (!is_numeric($number)) {
            throw new Error('Number input is not numeric');
        } else {
            if ($number % 2 == 0) {
                return true;
            } else {
                return false;
            }
        }
    }
}
/*
|--------------------------------------------------------------------------
| jsonEncode
|--------------------------------------------------------------------------
|
| return Encode simple php array to jsone object
| in json_encode php will return an array in json format
| the keys will be 0 to end numbers.
|
*/
if (! function_exists('jsonEncode')) {
    function jsonEncode($generator)
    {
        $output = array();
        foreach ($generator as $key => $item) {
            $output[$key] = $item;
        }
        return json_encode($output);
    }
}
/*
|--------------------------------------------------------------------------
| fa_to_en
|--------------------------------------------------------------------------
|
| get persian uumber and return en number
| used when saving data to database
|
|
*/
if (! function_exists('fa_to_en')) {
    function fa_to_en($number)
    {
        if (empty($number)) return '0';

        $en = array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
        $fa = array("۰", "۱", "۲", "۳", "۴", "۵", "۶", "۷", "۸", "۹");

        return str_replace($fa, $en, $number);
    }
}

/*
|--------------------------------------------------------------------------
| en_to_fa
|--------------------------------------------------------------------------
|
| get en  uumber and return persian number
| used when show data from database to user
|
|
*/
if (! function_exists('en_to_fa')) {
    function en_to_fa($number)
    {
        if (empty($number)) return '۰';

        $en = array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
        $fa = array("۰", "۱", "۲", "۳", "۴", "۵", "۶", "۷", "۸", "۹");

        return str_replace($en, $fa, $number);
    }
}

/*
|--------------------------------------------------------------------------
| price_format
|--------------------------------------------------------------------------
|
| get en price and return persian price
|
|
|
*/
if (! function_exists('price_format')) {
    function price_format(string $price,string $unit="تومان") {
        return en_to_fa(number_format((float)$price)) . $unit;
    }
}
/*
|--------------------------------------------------------------------------
| getIp
|--------------------------------------------------------------------------
|
| get client ip address
|
|
|
*/
if (! function_exists('getIp')) {
    function getIp() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return $ip;
    }
}
/*
|--------------------------------------------------------------------------
| getTime
|--------------------------------------------------------------------------
|
| return time as timestamp;
|
|
*/
if (! function_exists('getTime')) {
    function getTime($year = -1, $month = -1, $day = -1, $hour = -1, $minute = -1, $second = -1, $time = -1) {
        if ($time == -1) $time = time();
        if ($year == -1) $year = date('Y', $time);
        if ($month == -1) $month = date('m', $time);
        if ($day == -1) $day = date('d', $time);
        if ($hour == -1) $hour = date('H', $time);
        if ($minute == -1) $minute = date('i', $time);
        if ($second == -1) $second = date('s', $time);
        return mktime($hour, $minute, $second, $month, $day, $year);
    }
}

/*
|--------------------------------------------------------------------------
| whichPartUrl
|--------------------------------------------------------------------------
|
| get hole url as string return spesefic part of it
|
|
*/
if (! function_exists('whichPartUrl')) {
    function whichPartUrl($url ='',$partNumber=0){
        if($url != ''){
          $url = strval($url);
          $url=str_replace("http://","",$url);
          $url=str_replace("https://","",$url);
          $thisPart = explode("/",$url);
        return $thisPart[$partNumber];
        }
        else{
            return false;
        }
    }
}

/*
|--------------------------------------------------------------------------
| whichcrud
|--------------------------------------------------------------------------
|
| get last part of url and seprate it by dash - then return first part
|
|
*/
if (! function_exists('whichcrud')) {
    function whichcrud(string $urlpart="add-user"){
        $thisPart = explode("-",$urlpart);
        return $thisPart[0];
    }
}

/*
|--------------------------------------------------------------------------
| tarjome
|--------------------------------------------------------------------------
|
| translate text without api
|
|
*/

if(! function_exists('tarjome')){
    function tarjome(string $source='en',string $target = 'fa',string $text="hi"){
        return GoogleTranslate::translate($source, $target, $text);
    }
}

if(! function_exists("parsi_date")){
    function parsi_date(string $format="y/m/d",string $thedate = "now"){
        $Jdate = new Jdate();
        return $Jdate->jdate($format,$thedate);
    }
}

/*
|--------------------------------------------------------------------------
| submit_btn
|--------------------------------------------------------------------------
|
| create submit button base on massage the massage string base on mdbootstrap background color
|
|
*/
if(!  function_exists("submit_btn")) {
    function submit_btn(string $status = "success",string $id="add-user",string $message="")
    {
        return "<a class='btn btn-" . $status . " submit-btn' type='submit' id='".$id."'><i class='fas fa-check'></i>" . $message . "</a>";
    }
}

/*
|--------------------------------------------------------------------------
| submit_btn
|--------------------------------------------------------------------------
|
| create submit button base on massage the massage string base on mdbootstrap background color
|
|
*/
if(! function_exists('make_js_path')) {
    function make_js_path(string $url)
    {
        return "<script src='" . url("/") . "/dashboard/js/" . whichPartUrl($url, 2) . ".js'></script>";
    }
}

/*
|--------------------------------------------------------------------------
| gnerate_img_file_name
|--------------------------------------------------------------------------
|
| image file names can be wrong for seo so we regenerate them
|
|
*/
if(!function_exists("gnerate_img_file_name")) {
    function gnerate_img_file_name()
    {
        return uniqid('report-img-');
    }
}


/*
|--------------------------------------------------------------------------
| faDateToTimestamp
|--------------------------------------------------------------------------
|
| get persian date as string rrturn time stamp of that date for save in database
|
|
*/
if(!function_exists("faDateToTimestamp")) {
    function faDateToTimestamp(string $string="1400/01/01"){
        $Jdate = new Jdate();
        return $Jdate->persianStrToTime($string);
    }
}
