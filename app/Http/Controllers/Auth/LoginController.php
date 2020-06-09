<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Carbon\Carbon;
use App\User;
use Exception;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
class LoginController extends Controller
{
    function redirectToGoogle(){
        return Socialite::driver('google')->stateless()->redirect();
    }
    function handleGoogleCallback(){
        try{
            $user = Socialite::driver('google')->stateless()->user();
            $existingUser = User::where('email', $user->email)->first();
            if($existingUser){
                Auth::login($existingUser);
                $tokenResult = $existingUser->createToken('Personal Access Token');
                $token = $tokenResult->token;
                $token->save();
                $data['token'] = $tokenResult->accessToken;
                $data['expired_at'] = Carbon::parse($tokenResult->token->expires_at)->toDateTimeString();
            }else{
                $newUser = new User([
                    'name' => $user->name,
                    'email' => $user->email,
                    'password' => bcrypt(Str::random(40)),
                    'email_verified_at' => Carbon::now()->timestamp,
                    'google_id' => $user->id,
                ]);
                $newUser->save();
                $tokenResult = $newUser->createToken('Personal Access Token');
                $token = $tokenResult->token;
                $data['token'] = $tokenResult->accessToken;
                $data['expired_at'] = Carbon::parse($tokenResult->token->expires_at)->toDateTimeString();
                $token->save();
                
            }
        }catch(Exception $err){
            Log::debug($err);
            return response()->json([
                "message" => $err->getMessage()
            ]);
        }
        return response()->json([
            "data" => $data
        ]);
    }
}
