class c449 {
   public static void main(String[] var0) throws Exception {
      System.out.print("Paving your way.");
      pave("");
   }

   public static void pave(String var0) throws Exception {
      var0 = var0 + "B";
      System.out.print(".");
      Thread.sleep(3600000L);
      c614.pave(var0);
   }
}
