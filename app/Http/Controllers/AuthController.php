<?php

namespace App\Http\Controllers;

use auth;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request){
        $fields = $request->validate([
            'name' => 'required|string',
            //the email field must be unique in the users table
            'email'=> 'required|string|unique:users,email',
            //the password field must be confirmed by the user in a (password_confirmation) field
            'password'=> 'required|string|confirmed'
        ]);

        $user = User::create([
            'name'=> $fields['name'],
            'email'=> $fields['email'],
            'password'=> bcrypt($fields['password'])
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response=[
            'user'=> $user,
            'token'=> $token
        ];

        return response($response, 201);
    }

    public function logout(Request $request){
        //delete th euser tokem form the database 
        auth()->user()->tokens()->delete();

        return [
            'message'=> 'Logged out'
        ];
    }

    public function login(Request $request){
        $fields = $request->validate([
            //the email field must be unique in the users table
            'email'=> 'required|string',
            //the password field must be confirmed by the user in a (password_confirmation) field
            'password'=> 'required|string'
        ]);

        //check email
        $user = User::where('email', $fields['email'])->first();

        //check password
        if(!$user || !Hash::check($fields['password'], $user->password)){

            return response(
                [
                    'message'=> 'bad creds'
                ], 401);
        }


        $token = $user->createToken('myapptoken')->plainTextToken;

        $response=[
            'user'=> $user,
            'token'=> $token
        ];

        return response($response, 201);
    }
}
